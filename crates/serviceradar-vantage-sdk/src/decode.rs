// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust H.264 IDR, Baseline JPEG (`zune-jpeg`), and RGB8 frame decoding.

use crate::cmaf::{ParsedInitSegment, ParsedMediaFragment, VideoCodec};
use crate::error::VantageError;
use crate::frame::{MAX_FRAME_DIMENSION, RgbFrame};
use crate::protocol::{LiveFrameCarrier, VantageLiveFrameEnvelope};
use std::collections::HashMap;
use std::io::Cursor;
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;

pub const MAX_KEYFRAME_ACCESS_UNIT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PARAMETER_SET_BYTES: usize = 4096;

const NAL_SPS: u8 = 7;
const NAL_PPS: u8 = 8;
const NAL_IDR: u8 = 5;

const PROFILE_BASELINE: u8 = 66;
const PROFILE_MAIN: u8 = 77;
const PROFILE_HIGH: u8 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YuvMatrix {
    Bt601,
    Bt709,
    Bt2020,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColourSpec {
    matrix: YuvMatrix,
    full_range: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpsInfo {
    frame_num_bits: u32,
    frame_mbs_only: bool,
    poc_lsb_bits: Option<u32>,
    delta_poc_present: bool,
    crop_left: u32,
    crop_top: u32,
    display_width: u32,
    display_height: u32,
    full_range: Option<bool>,
    matrix_coefficients: Option<u8>,
}

/// Decodes a verified CMAF fragment's IDR keyframe into an [`RgbFrame`].
pub fn decode_cmaf_keyframe(
    init: &ParsedInitSegment,
    fragment: &ParsedMediaFragment,
) -> Result<RgbFrame, VantageError> {
    match init.codec {
        VideoCodec::H264 => {
            let parameter_sets: Vec<&[u8]> = init
                .parameter_sets
                .iter()
                .chain(fragment.in_band_parameter_sets.iter())
                .map(Vec::as_slice)
                .collect();
            let slices: Vec<&[u8]> = fragment.idr_nal_units.iter().map(Vec::as_slice).collect();
            decode_h264_access_unit(&parameter_sets, &slices)
        }
        VideoCodec::Hevc => Err(VantageError::decode(
            "unsupported_codec",
            "hevc: SDK decodes H.264 only",
        )),
    }
}

/// Decodes an Annex-B H.264 IDR byte stream (e.g. `live_keyframe_tap` carrier) into [`RgbFrame`].
pub fn decode_annex_b_idr(annex_b: &[u8]) -> Result<RgbFrame, VantageError> {
    let nals = split_annex_b_nals(annex_b);
    if nals.is_empty() {
        return Err(VantageError::decode(
            "malformed_bitstream",
            "Annex-B payload contains no NAL units",
        ));
    }
    let mut parameter_sets = Vec::new();
    let mut idr_slices = Vec::new();
    for nal in nals {
        match nal_type(nal) {
            Some(NAL_SPS | NAL_PPS) => parameter_sets.push(nal),
            Some(NAL_IDR) => idr_slices.push(nal),
            _ => {}
        }
    }
    decode_h264_access_unit(&parameter_sets, &idr_slices)
}

/// Splits an Annex-B byte stream (`00 00 01` or `00 00 00 01` start codes) into raw NAL slices.
pub fn split_annex_b_nals(mut data: &[u8]) -> Vec<&[u8]> {
    let mut offsets = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if i + 4 <= data.len() && data[i..i + 4] == [0, 0, 0, 1] {
            offsets.push((i, 4));
            i += 4;
        } else if data[i..i + 3] == [0, 0, 1] {
            offsets.push((i, 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut nals = Vec::with_capacity(offsets.len());
    for (idx, &(start, sc_len)) in offsets.iter().enumerate() {
        let nal_start = start + sc_len;
        let nal_end = offsets
            .get(idx + 1)
            .map(|&(next_s, _)| next_s)
            .unwrap_or(data.len());
        if nal_start < nal_end {
            nals.push(&data[nal_start..nal_end]);
        }
    }
    let _ = &mut data;
    nals
}

/// Decodes a JPEG byte slice into an [`RgbFrame`] using pure-Rust `zune-jpeg`.
pub fn decode_jpeg_to_rgb(jpeg_bytes: &[u8]) -> Result<RgbFrame, VantageError> {
    let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB);
    let mut decoder = JpegDecoder::new_with_options(Cursor::new(jpeg_bytes), options);
    let pixels = decoder.decode().map_err(|err| {
        VantageError::decode("malformed_bitstream", format!("JPEG decode failed: {err}"))
    })?;
    let info = decoder.info().ok_or_else(|| {
        VantageError::decode("malformed_bitstream", "JPEG decoder missing image info")
    })?;
    let w = u32::from(info.width);
    let h = u32::from(info.height);
    let expected_rgb = (w as usize) * (h as usize) * 3;
    let rgb = if pixels.len() == expected_rgb {
        pixels
    } else if pixels.len() == (w as usize) * (h as usize) {
        let mut expanded = Vec::with_capacity(expected_rgb);
        for y in pixels {
            expanded.extend_from_slice(&[y, y, y]);
        }
        expanded
    } else {
        return Err(VantageError::invalid_frame(format!(
            "decoded JPEG byte length {} does not match RGB8 {}x{}",
            pixels.len(),
            w,
            h
        )));
    };
    RgbFrame::from_rgb8(w, h, rgb)
}

/// Validates and decodes any supported `VantageLiveFrameEnvelope` carrier (`jpeg`, `annex_b_idr`, `rgb8`).
pub fn decode_live_frame_envelope(
    env: &VantageLiveFrameEnvelope,
) -> Result<RgbFrame, VantageError> {
    match env.validate()? {
        LiveFrameCarrier::Jpeg(bytes) => decode_jpeg_to_rgb(&bytes),
        LiveFrameCarrier::AnnexBIdr(bytes) => decode_annex_b_idr(&bytes),
        LiveFrameCarrier::Rgb8 {
            width,
            height,
            bytes,
        } => {
            let (w, h) = match (width, height) {
                (Some(w), Some(h)) => (w, h),
                _ => {
                    let px = bytes.len() / 3;
                    let w = u32::try_from(px)
                        .map_err(|_| VantageError::invalid_frame("rgb8 width overflow"))?;
                    (w, 1)
                }
            };
            RgbFrame::from_rgb8(w, h, bytes)
        }
    }
}

/// Decodes an H.264 IDR access unit (without length prefixes or start codes) to [`RgbFrame`].
pub fn decode_h264_access_unit(
    parameter_sets: &[&[u8]],
    slices: &[&[u8]],
) -> Result<RgbFrame, VantageError> {
    let slice = match *slices {
        [slice] => slice,
        [] => {
            return Err(VantageError::decode(
                "malformed_bitstream",
                "keyframe sample carries no IDR slice",
            ));
        }
        _ => {
            return Err(VantageError::decode(
                "unsupported_codec",
                "multi-slice pictures not yet supported",
            ));
        }
    };

    let mut sps_by_id = HashMap::new();
    let mut pps_by_id = HashMap::new();
    for &nal in parameter_sets {
        if nal.len() > MAX_PARAMETER_SET_BYTES {
            return Err(VantageError::decode(
                "limit_exceeded",
                "parameter set exceeds byte limit",
            ));
        }
        match nal_type(nal) {
            Some(NAL_SPS) => {
                let rbsp = nal_rbsp(nal, 16)?;
                let mut reader = BitReader::new(&rbsp);
                let (id, _) = sps_header(&mut reader)?;
                sps_by_id.insert(id, nal);
            }
            Some(NAL_PPS) => {
                let rbsp = nal_rbsp(nal, 16)?;
                let mut reader = BitReader::new(&rbsp);
                pps_by_id.insert(reader.read_ue_max(255, "pic_parameter_set_id")?, nal);
            }
            _ => continue,
        }
    }
    let slice_bytes = slice.len() + 4;
    if slice_bytes > MAX_KEYFRAME_ACCESS_UNIT_BYTES {
        return Err(VantageError::decode(
            "limit_exceeded",
            "keyframe access unit exceeds byte limit",
        ));
    }

    let header = slice_header_prefix(slice)?;
    let mut slice_reader = BitReader::new(&header);
    let first_mb = slice_reader.read_ue()?;
    let slice_type = slice_reader.read_ue_max(9, "slice_type")?;
    let pps_id = slice_reader.read_ue_max(255, "pic_parameter_set_id")?;
    let pps = *pps_by_id.get(&pps_id).ok_or_else(|| {
        VantageError::decode("malformed_bitstream", "IDR slice references missing PPS")
    })?;
    let pps_rbsp = nal_rbsp(pps, pps.len())?;
    let mut pps_reader = BitReader::parameter_set(&pps_rbsp);
    let sps_id = pps_sps_id(&mut pps_reader)?;
    let sps_nal = *sps_by_id
        .get(&sps_id)
        .ok_or_else(|| VantageError::decode("malformed_bitstream", "PPS references missing SPS"))?;
    let sps_rbsp = nal_rbsp(sps_nal, sps_nal.len())?;
    let mut sps_reader = BitReader::parameter_set(&sps_rbsp);
    let (_, profile) = sps_header(&mut sps_reader)?;
    validate_layout(profile, &mut sps_reader)?;
    let sps = parse_supported_sps(profile, &mut sps_reader)?;
    let active_pps = parse_supported_pps(&mut pps_reader)?;
    let colour = colour_spec(&sps)?;

    let total_bytes = slice_bytes + sps_nal.len() + pps.len() + 8;
    if total_bytes > MAX_KEYFRAME_ACCESS_UNIT_BYTES {
        return Err(VantageError::decode(
            "limit_exceeded",
            "keyframe access unit exceeds byte limit",
        ));
    }
    validate_idr_slice(&mut slice_reader, first_mb, slice_type, &sps, &active_pps)?;

    let mut annex_b = Vec::with_capacity(total_bytes);
    for nal in [sps_nal, pps, slice] {
        annex_b.extend_from_slice(&[0, 0, 0, 1]);
        annex_b.extend_from_slice(nal);
    }
    let frame = rusty_h264_decoder::Decoder::new()
        .decode(&annex_b)
        .map_err(|err| VantageError::decode("malformed_bitstream", err.to_string()))?
        .ok_or_else(|| VantageError::decode("malformed_bitstream", "incomplete IDR picture"))?;

    let (width, height) = (frame.width, frame.height);
    let luma_len = width.checked_mul(height);
    let chroma_len = (width / 2).checked_mul(height / 2);
    if width != (sps.display_width + sps.crop_left) as usize
        || height != (sps.display_height + sps.crop_top) as usize
        || width % 2 != 0
        || height % 2 != 0
        || luma_len != Some(frame.y.len())
        || chroma_len != Some(frame.u.len())
        || chroma_len != Some(frame.v.len())
    {
        return Err(VantageError::decode(
            "malformed_bitstream",
            format!(
                "decoded picture {width}x{height} does not match SPS display size {}x{}",
                sps.display_width, sps.display_height
            ),
        ));
    }

    let y = crop_plane(
        frame.y,
        width,
        sps.crop_left as usize,
        sps.crop_top as usize,
    );
    let u = crop_plane(
        frame.u,
        width / 2,
        sps.crop_left as usize / 2,
        sps.crop_top as usize / 2,
    );
    let v = crop_plane(
        frame.v,
        width / 2,
        sps.crop_left as usize / 2,
        sps.crop_top as usize / 2,
    );

    picture_to_rgb(
        sps.display_width as usize,
        sps.display_height as usize,
        &y,
        &u,
        &v,
        colour,
    )
}

fn validate_idr_slice(
    r: &mut BitReader<'_>,
    first_mb: u32,
    slice_type: u32,
    sps: &SpsInfo,
    pps: &PpsInfo,
) -> Result<(), VantageError> {
    match slice_type {
        2 | 7 => {}
        4 | 9 => return Err(VantageError::decode("unsupported_codec", "SI slice")),
        _ => {
            return Err(VantageError::decode(
                "malformed_bitstream",
                "non-intra slice in IDR",
            ));
        }
    }
    r.read_bits(sps.frame_num_bits)?;
    if !sps.frame_mbs_only && r.read_flag()? {
        return Err(VantageError::decode("unsupported_codec", "field picture"));
    }
    if first_mb != 0 {
        return Err(VantageError::decode(
            "malformed_bitstream",
            "single slice must start at macroblock zero",
        ));
    }
    r.read_ue_max(65_535, "idr_pic_id")?;
    if let Some(bits) = sps.poc_lsb_bits {
        r.read_bits(bits)?;
    }
    if sps.delta_poc_present {
        r.read_se()?;
    }
    if pps.bottom_field_pic_order_present && (sps.poc_lsb_bits.is_some() || sps.delta_poc_present) {
        r.read_se()?;
    }
    if pps.redundant_pic_cnt_present_flag {
        r.read_ue_max(127, "redundant_pic_cnt")?;
    }
    r.read_bits(2)?;
    let slice_qp = pps.pic_init_qp + r.read_se()?;
    if !(0..=51).contains(&slice_qp) {
        return Err(VantageError::decode(
            "malformed_bitstream",
            "invalid slice QP",
        ));
    }
    if pps.deblocking_filter_control_present_flag
        && r.read_ue_max(2, "disable_deblocking_filter_idc")? != 1
    {
        let alpha = r.read_se()?;
        let beta = r.read_se()?;
        if !(-6..=6).contains(&alpha) || !(-6..=6).contains(&beta) {
            return Err(VantageError::decode(
                "malformed_bitstream",
                "invalid deblocking offset",
            ));
        }
    }
    Ok(())
}

fn crop_plane(mut plane: Vec<u8>, stride: usize, left: usize, top: usize) -> Vec<u8> {
    if left != 0 || top != 0 {
        let width = stride - left;
        let rows = plane.len() / stride - top;
        for row in 0..rows {
            let start = (row + top) * stride + left;
            plane.copy_within(start..start + width, row * width);
        }
        plane.truncate(rows * width);
    }
    plane
}

fn nal_type(nal: &[u8]) -> Option<u8> {
    let header = *nal.first()?;
    (header & 0x80 == 0).then_some(header & 0x1f)
}

fn colour_spec(sps: &SpsInfo) -> Result<ColourSpec, VantageError> {
    let by_size = if sps.display_height > 576 {
        YuvMatrix::Bt709
    } else {
        YuvMatrix::Bt601
    };
    let matrix = match sps.matrix_coefficients {
        Some(1) => YuvMatrix::Bt709,
        Some(5 | 6) => YuvMatrix::Bt601,
        Some(9) => YuvMatrix::Bt2020,
        None | Some(2) => by_size,
        Some(code) => {
            return Err(VantageError::decode(
                "unsupported_codec",
                format!("h264 VUI matrix_coefficients {code} unsupported"),
            ));
        }
    };
    Ok(ColourSpec {
        matrix,
        full_range: sps.full_range.unwrap_or(false),
    })
}

fn picture_to_rgb(
    width: usize,
    height: usize,
    y_plane: &[u8],
    u_plane: &[u8],
    v_plane: &[u8],
    colour: ColourSpec,
) -> Result<RgbFrame, VantageError> {
    let coeffs = RgbCoefficients::new(colour);
    let chroma_width = width / 2;
    let mut rgb = vec![0u8; width * height * 3];
    for (row, out_row) in rgb.chunks_exact_mut(width * 3).enumerate() {
        let y_row = &y_plane[row * width..(row + 1) * width];
        let c_start = (row / 2) * chroma_width;
        let u_row = &u_plane[c_start..c_start + chroma_width];
        let v_row = &v_plane[c_start..c_start + chroma_width];
        for (col, px) in out_row.as_chunks_mut::<3>().0.iter_mut().enumerate() {
            let conv = coeffs.convert(y_row[col], u_row[col / 2], v_row[col / 2]);
            px[0] = conv[0];
            px[1] = conv[1];
            px[2] = conv[2];
        }
    }
    let w = u32::try_from(width)
        .map_err(|_| VantageError::decode("limit_exceeded", "picture width overflows u32"))?;
    let h = u32::try_from(height)
        .map_err(|_| VantageError::decode("limit_exceeded", "picture height overflows u32"))?;
    RgbFrame::from_rgb8(w, h, rgb)
}

#[derive(Debug, Clone, Copy)]
struct RgbCoefficients {
    y_offset: i32,
    y_scale: i32,
    r_v: i32,
    g_u: i32,
    g_v: i32,
    b_u: i32,
}

impl RgbCoefficients {
    fn new(colour: ColourSpec) -> Self {
        let (kr, kb) = match colour.matrix {
            YuvMatrix::Bt601 => (0.299_f64, 0.114_f64),
            YuvMatrix::Bt709 => (0.2126, 0.0722),
            YuvMatrix::Bt2020 => (0.2627, 0.0593),
        };
        let kg = 1.0 - kr - kb;
        let (y_offset, y_scale, c_scale) = if colour.full_range {
            (0, 1.0, 1.0)
        } else {
            (16, 255.0 / 219.0, 255.0 / 224.0)
        };
        let fixed = |v: f64| (v * 65_536.0).round() as i32;
        Self {
            y_offset,
            y_scale: fixed(y_scale),
            r_v: fixed(c_scale * 2.0 * (1.0 - kr)),
            g_u: fixed(c_scale * 2.0 * kb * (1.0 - kb) / kg),
            g_v: fixed(c_scale * 2.0 * kr * (1.0 - kr) / kg),
            b_u: fixed(c_scale * 2.0 * (1.0 - kb)),
        }
    }

    fn convert(&self, y: u8, u: u8, v: u8) -> [u8; 3] {
        let y = (i32::from(y) - self.y_offset) * self.y_scale;
        let u = i32::from(u) - 128;
        let v = i32::from(v) - 128;
        let clamp = |value: i32| ((value + 32_768) >> 16).clamp(0, 255) as u8;
        [
            clamp(y + self.r_v * v),
            clamp(y - self.g_u * u - self.g_v * v),
            clamp(y + self.b_u * u),
        ]
    }
}

enum SyntaxError {
    Truncated,
    Invalid(VantageError),
}

impl From<VantageError> for SyntaxError {
    fn from(error: VantageError) -> Self {
        Self::Invalid(error)
    }
}

impl From<SyntaxError> for VantageError {
    fn from(error: SyntaxError) -> Self {
        match error {
            SyntaxError::Truncated => Self::decode("malformed_bitstream", "truncated H.264 syntax"),
            SyntaxError::Invalid(err) => err,
        }
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
    end: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bit: 0,
            end: data.len() * 8,
        }
    }

    fn parameter_set(data: &'a [u8]) -> Self {
        let end = data
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i * 8 + 7 - data[i].trailing_zeros() as usize);
        Self { data, bit: 0, end }
    }

    fn read_bit(&mut self) -> Result<u32, SyntaxError> {
        if self.bit == self.end {
            return Err(SyntaxError::Truncated);
        }
        let byte = self.data[self.bit / 8];
        let value = (byte >> (7 - (self.bit % 8))) & 1;
        self.bit += 1;
        Ok(u32::from(value))
    }

    fn read_bits(&mut self, count: u32) -> Result<u32, SyntaxError> {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }

    fn read_flag(&mut self) -> Result<bool, SyntaxError> {
        Ok(self.read_bit()? == 1)
    }

    fn read_ue(&mut self) -> Result<u32, SyntaxError> {
        let mut leading_zeros = 0u32;
        while self.read_bit()? == 0 {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return Err(VantageError::decode(
                    "malformed_bitstream",
                    "h264 Exp-Golomb code > 32 bits",
                )
                .into());
            }
        }
        let suffix = self.read_bits(leading_zeros)?;
        let value = (1u64 << leading_zeros) - 1 + u64::from(suffix);
        u32::try_from(value).map_err(|_| {
            VantageError::decode("malformed_bitstream", "h264 Exp-Golomb overflow").into()
        })
    }

    fn read_se(&mut self) -> Result<i64, SyntaxError> {
        let code = i64::from(self.read_ue()?);
        Ok(if code % 2 == 1 {
            (code + 1) / 2
        } else {
            -(code / 2)
        })
    }

    fn read_ue_max(&mut self, max: u32, field: &str) -> Result<u32, SyntaxError> {
        let value = self.read_ue()?;
        if value > max {
            return Err(VantageError::decode(
                "malformed_bitstream",
                format!("h264 {field} {value} exceeds {max}"),
            )
            .into());
        }
        Ok(value)
    }
}

fn nal_rbsp(nal: &[u8], retain: usize) -> Result<Vec<u8>, SyntaxError> {
    let payload = nal.get(1..).ok_or(SyntaxError::Truncated)?;
    let mut rbsp = Vec::with_capacity(retain.min(payload.len()));
    let mut zeros = 0;
    for (index, &byte) in payload.iter().enumerate() {
        if zeros == 2 {
            match byte {
                0..=2 => {
                    return Err(VantageError::decode(
                        "malformed_bitstream",
                        "unescaped H.264 byte sequence",
                    )
                    .into());
                }
                3 => match payload.get(index + 1) {
                    Some(0..=3) => {
                        zeros = 0;
                        continue;
                    }
                    None if nal_type(nal) == Some(NAL_IDR) => {}
                    None => return Err(SyntaxError::Truncated),
                    Some(_) => {
                        return Err(VantageError::decode(
                            "malformed_bitstream",
                            "invalid emulation-prevention byte",
                        )
                        .into());
                    }
                },
                _ => {}
            }
        }
        if rbsp.len() < retain {
            rbsp.push(byte);
        }
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    Ok(rbsp)
}

struct PpsInfo {
    pic_init_qp: i64,
    bottom_field_pic_order_present: bool,
    deblocking_filter_control_present_flag: bool,
    redundant_pic_cnt_present_flag: bool,
}

fn pps_sps_id(r: &mut BitReader<'_>) -> Result<u32, SyntaxError> {
    r.read_ue_max(255, "pic_parameter_set_id")?;
    r.read_ue_max(31, "seq_parameter_set_id")
}

fn parse_supported_pps(r: &mut BitReader<'_>) -> Result<PpsInfo, SyntaxError> {
    r.read_flag()?;
    let bottom_field_pic_order_present = r.read_flag()?;
    if r.read_ue()? != 0 {
        return Err(VantageError::decode("unsupported_codec", "slice groups (FMO)").into());
    }
    r.read_ue_max(31, "num_ref_idx_l0_default_active_minus1")?;
    r.read_ue_max(31, "num_ref_idx_l1_default_active_minus1")?;
    r.read_bits(3)?;
    let pic_init_qp = 26 + r.read_se()?;
    if !(0..=51).contains(&pic_init_qp) {
        return Err(VantageError::decode("malformed_bitstream", "invalid initial QP").into());
    }
    r.read_se()?;
    let cb = r.read_se()?;
    let deblocking_filter_control_present_flag = r.read_flag()?;
    r.read_flag()?;
    let redundant_pic_cnt_present_flag = r.read_flag()?;
    let cr = if r.bit < r.end {
        let transform_8x8 = r.read_flag()?;
        if r.read_flag()? {
            read_scaling_lists(r, if transform_8x8 { 8 } else { 6 })?;
        }
        r.read_se()?
    } else {
        cb
    };
    if !(-12..=12).contains(&cb) || !(-12..=12).contains(&cr) {
        return Err(VantageError::decode("malformed_bitstream", "invalid chroma QP").into());
    }
    if cb != cr {
        return Err(
            VantageError::decode("unsupported_codec", "unequal Cb and Cr QP offsets").into(),
        );
    }
    Ok(PpsInfo {
        pic_init_qp,
        bottom_field_pic_order_present,
        deblocking_filter_control_present_flag,
        redundant_pic_cnt_present_flag,
    })
}

fn sps_header(r: &mut BitReader<'_>) -> Result<(u32, u8), SyntaxError> {
    let profile_idc = r.read_bits(8)? as u8;
    r.read_bits(16)?;
    Ok((r.read_ue_max(31, "seq_parameter_set_id")?, profile_idc))
}

fn validate_layout(profile_idc: u8, r: &mut BitReader<'_>) -> Result<(), SyntaxError> {
    if !matches!(profile_idc, PROFILE_BASELINE | PROFILE_MAIN | PROFILE_HIGH) {
        return Err(VantageError::decode(
            "unsupported_codec",
            format!("h264 profile_idc {profile_idc}"),
        )
        .into());
    }
    if profile_idc == PROFILE_HIGH {
        if r.read_ue_max(3, "chroma_format_idc")? != 1 {
            return Err(
                VantageError::decode("unsupported_codec", "non-4:2:0 chroma format").into(),
            );
        }
        let luma_depth = r.read_ue_max(6, "bit_depth_luma_minus8")?;
        let chroma_depth = r.read_ue_max(6, "bit_depth_chroma_minus8")?;
        if luma_depth != 0 || chroma_depth != 0 {
            return Err(VantageError::decode("unsupported_codec", "non-8-bit picture").into());
        }
    }
    Ok(())
}

fn parse_supported_sps(profile_idc: u8, r: &mut BitReader<'_>) -> Result<SpsInfo, SyntaxError> {
    if profile_idc == PROFILE_HIGH {
        let _qpprime = r.read_flag()?;
        if r.read_flag()? {
            read_scaling_lists(r, 8)?;
        }
    }
    let frame_num_bits = 4 + r.read_ue_max(12, "log2_max_frame_num_minus4")?;
    let mut poc_lsb_bits = None;
    let mut delta_poc_present = false;
    match r.read_ue_max(2, "pic_order_cnt_type")? {
        0 => {
            poc_lsb_bits = Some(4 + r.read_ue_max(12, "log2_max_pic_order_cnt_lsb_minus4")?);
        }
        1 => {
            delta_poc_present = !r.read_flag()?;
            let _ = r.read_se()?;
            let _ = r.read_se()?;
            let cycle = r.read_ue_max(255, "num_ref_frames_in_pic_order_cnt_cycle")?;
            for _ in 0..cycle {
                let _ = r.read_se()?;
            }
        }
        _ => {}
    }
    let _max_num_ref_frames = r.read_ue()?;
    let _gaps = r.read_flag()?;
    let width_in_mbs = 1 + u64::from(r.read_ue()?);
    let height_in_map_units = 1 + u64::from(r.read_ue()?);
    let frame_mbs_only = r.read_flag()?;
    if !frame_mbs_only && r.read_flag()? {
        return Err(VantageError::decode("unsupported_codec", "MBAFF picture").into());
    }
    let _direct_8x8 = r.read_flag()?;
    let coded_width = width_in_mbs * 16;
    let coded_height = height_in_map_units * 16 * if frame_mbs_only { 1 } else { 2 };

    if coded_width > u64::from(MAX_FRAME_DIMENSION) || coded_height > u64::from(MAX_FRAME_DIMENSION)
    {
        return Err(VantageError::decode(
            "limit_exceeded",
            "coded picture exceeds dimension limit",
        )
        .into());
    }
    let (coded_width, coded_height) = (coded_width as u32, coded_height as u32);
    let (mut crop_left, mut crop_top) = (0, 0);
    let (mut crop_x, mut crop_y) = (0u32, 0u32);
    if r.read_flag()? {
        let left = r.read_ue()?;
        let right = r.read_ue()?;
        let top = r.read_ue()?;
        let bottom = r.read_ue()?;
        let unit_y = if frame_mbs_only { 2 } else { 4 };
        crop_left = left.saturating_mul(2);
        crop_top = top.saturating_mul(unit_y);
        crop_x = left
            .checked_add(right)
            .and_then(|sum| sum.checked_mul(2))
            .unwrap_or(u32::MAX);
        crop_y = top
            .checked_add(bottom)
            .and_then(|sum| sum.checked_mul(unit_y))
            .unwrap_or(u32::MAX);
        if crop_x >= coded_width || crop_y >= coded_height {
            return Err(VantageError::decode(
                "malformed_bitstream",
                "h264 SPS cropping window exceeds coded picture",
            )
            .into());
        }
    }

    let (full_range, matrix_coefficients) = if r.read_flag()? {
        parse_vui_colour(r).unwrap_or((None, None))
    } else {
        (None, None)
    };

    Ok(SpsInfo {
        frame_num_bits,
        frame_mbs_only,
        poc_lsb_bits,
        delta_poc_present,
        crop_left,
        crop_top,
        display_width: coded_width - crop_x,
        display_height: coded_height - crop_y,
        full_range,
        matrix_coefficients,
    })
}

fn read_scaling_lists(r: &mut BitReader<'_>, count: usize) -> Result<(), SyntaxError> {
    for index in 0..count {
        if r.read_flag()? {
            skip_scaling_list(r, if index < 6 { 16 } else { 64 })?;
        }
    }
    Ok(())
}

fn skip_scaling_list(r: &mut BitReader<'_>, size: usize) -> Result<(), SyntaxError> {
    let mut last_scale = 8i64;
    let mut next_scale = 8i64;
    for _ in 0..size {
        if next_scale != 0 {
            let delta = r.read_se()?;
            if !(-128..=127).contains(&delta) {
                return Err(VantageError::decode(
                    "malformed_bitstream",
                    "scaling list delta_scale out of range",
                )
                .into());
            }
            next_scale = (last_scale + delta + 256) % 256;
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Ok(())
}

fn parse_vui_colour(r: &mut BitReader<'_>) -> Result<(Option<bool>, Option<u8>), SyntaxError> {
    if r.read_flag()? {
        let aspect_ratio_idc = r.read_bits(8)?;
        if aspect_ratio_idc == 255 {
            let _ = r.read_bits(16)?;
            let _ = r.read_bits(16)?;
        }
    }
    if r.read_flag()? {
        let _ = r.read_flag()?;
    }
    if !r.read_flag()? {
        return Ok((None, None));
    }
    let _ = r.read_bits(3)?;
    let full_range = r.read_flag()?;
    let matrix = if r.read_flag()? {
        let _ = r.read_bits(8)?;
        let _ = r.read_bits(8)?;
        Some(r.read_bits(8)? as u8)
    } else {
        None
    };
    Ok((Some(full_range), matrix))
}

fn slice_header_prefix(nal: &[u8]) -> Result<Vec<u8>, VantageError> {
    if nal_type(nal) != Some(NAL_IDR) || nal[0] & 0x60 == 0 {
        return Err(VantageError::decode(
            "malformed_bitstream",
            "invalid IDR NAL header",
        ));
    }
    Ok(nal_rbsp(nal, 64)?)
}
