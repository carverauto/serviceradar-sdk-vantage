// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust ISO-BMFF / CMAF box parser (`ftyp`/`moov`/`avcC`/`hvcC`/`moof`/`traf`/`trun`/`mdat`)
//! plus progressive MP4 sync-sample extraction (`stts`/`stsc`/`stsz`/`stco`/`co64`/`stss`).

use crate::error::VantageError;
use crate::frame::MAX_FRAME_DIMENSION;

pub const MAX_SAMPLE_NAL_UNITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    H264,
    Hevc,
}

impl VideoCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInitSegment {
    pub codec: VideoCodec,
    pub in_band_avc_sets: bool,
    pub width: u32,
    pub height: u32,
    pub timescale: u32,
    pub nal_length_size: u8,
    pub parameter_sets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleTiming {
    pub decode_ticks: u64,
    pub cts_offset: i64,
}

impl SampleTiming {
    pub fn pts_ns(self, timescale: u32) -> u64 {
        if timescale == 0 {
            return 0;
        }
        let ticks = (self.decode_ticks as i128) + i128::from(self.cts_offset);
        let clamped = ticks.max(0) as u128;
        let ns = clamped.saturating_mul(1_000_000_000) / u128::from(timescale);
        u64::try_from(ns).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMediaFragment {
    pub sequence_number: u32,
    pub timing: SampleTiming,
    pub first_sample_size: usize,
    pub idr_nal_units: Vec<Vec<u8>>,
    pub in_band_parameter_sets: Vec<Vec<u8>>,
}

impl ParsedMediaFragment {
    pub fn media_pts_ns(&self, timescale: u32) -> u64 {
        self.timing.pts_ns(timescale)
    }
}

/// Sync sample extracted from a progressive (non-fragmented) MP4 file (`moov/trak/mdia/minf/stbl`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedMp4Sample {
    pub sample_index: u64,
    pub media_pts_ns: u64,
    pub idr_nal_units: Vec<Vec<u8>>,
    pub in_band_parameter_sets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
struct BoxView<'a> {
    box_type: [u8; 4],
    payload: &'a [u8],
}

fn read_box<'a>(buf: &mut &'a [u8]) -> Result<BoxView<'a>, VantageError> {
    if buf.len() < 8 {
        return Err(VantageError::invalid_container(
            "truncated ISO-BMFF box header (< 8 bytes)",
        ));
    }
    let size32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let box_type = [buf[4], buf[5], buf[6], buf[7]];

    let (header_len, total_len) = match size32 {
        0 => (8usize, buf.len()),
        1 => {
            if buf.len() < 16 {
                return Err(VantageError::invalid_container(
                    "truncated 64-bit largesize ISO-BMFF box header",
                ));
            }
            let size64 = u64::from_be_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            let len = usize::try_from(size64)
                .map_err(|_| VantageError::invalid_container("64-bit box size overflows usize"))?;
            if len < 16 {
                return Err(VantageError::invalid_container(
                    "invalid 64-bit box size < 16",
                ));
            }
            (16usize, len)
        }
        n if n < 8 => {
            return Err(VantageError::invalid_container(format!(
                "invalid ISO-BMFF box size {n} < 8"
            )));
        }
        n => (8usize, n as usize),
    };

    if total_len > buf.len() {
        return Err(VantageError::invalid_container(format!(
            "ISO-BMFF box '{}' size {} exceeds remaining {} bytes",
            core::str::from_utf8(&box_type).unwrap_or("????"),
            total_len,
            buf.len()
        )));
    }

    let payload = &buf[header_len..total_len];
    *buf = &buf[total_len..];
    Ok(BoxView { box_type, payload })
}

fn scan_boxes(mut buf: &[u8]) -> Result<Vec<BoxView<'_>>, VantageError> {
    let mut boxes = Vec::new();
    while !buf.is_empty() {
        boxes.push(read_box(&mut buf)?);
    }
    Ok(boxes)
}

/// Parses an ISO-BMFF / CMAF `init.mp4` segment (`ftyp` + `moov`).
pub fn parse_init_segment(init_bytes: &[u8]) -> Result<ParsedInitSegment, VantageError> {
    let top_boxes = scan_boxes(init_bytes)?;
    if !top_boxes.iter().any(|b| &b.box_type == b"ftyp") {
        return Err(VantageError::invalid_container(
            "init.mp4 missing required 'ftyp' box",
        ));
    }
    let moov = top_boxes
        .iter()
        .find(|b| &b.box_type == b"moov")
        .ok_or_else(|| VantageError::invalid_container("init.mp4 missing required 'moov' box"))?;

    let moov_children = scan_boxes(moov.payload)?;
    let mut movie_timescale = 90_000u32;
    if let Some(mvhd) = moov_children.iter().find(|b| &b.box_type == b"mvhd")
        && let Some(ts) = parse_mvhd_or_mdhd_timescale(mvhd.payload)
    {
        movie_timescale = ts;
    }

    for trak in moov_children.iter().filter(|b| &b.box_type == b"trak") {
        if let Some(parsed) = parse_video_trak(trak.payload, movie_timescale)? {
            return Ok(parsed);
        }
    }

    Err(VantageError::invalid_container(
        "init.mp4 contains no supported H.264 (avc1/avc3) or HEVC (hvc1/hev1) video track",
    ))
}

/// Parses either a fragmented CMAF stream (`moof`+`mdat`) OR a progressive MP4 (`moov`+`mdat`),
/// returning `(ParsedInitSegment, Vec<(fragment_seq, media_pts_ns, idr_nals, in_band_sets)>)`.
pub fn extract_mp4_sync_samples(
    mp4_bytes: &[u8],
) -> Result<(ParsedInitSegment, Vec<ExtractedMp4Sample>), VantageError> {
    let init = parse_init_segment(mp4_bytes)?;
    let top_boxes = scan_boxes(mp4_bytes)?;

    // 1. Check if the file contains `moof` fragments (single-file fMP4/CMAF).
    let has_moof = top_boxes.iter().any(|b| &b.box_type == b"moof");
    if has_moof {
        let mut samples = Vec::new();
        let mut idx = 0usize;
        while idx < top_boxes.len() {
            if &top_boxes[idx].box_type == b"moof" {
                let moof = top_boxes[idx];
                let mdat = top_boxes[idx + 1..]
                    .iter()
                    .find(|b| &b.box_type == b"mdat")
                    .ok_or_else(|| {
                        VantageError::invalid_container("CMAF fragment missing 'mdat' box")
                    })?;
                let mut timing = SampleTiming {
                    decode_ticks: 0,
                    cts_offset: 0,
                };
                let (seq, sample_bytes) = parse_moof_mdat(moof.payload, mdat.payload, &mut timing)?;
                let (idr_nals, in_band) = extract_keyframe_nal_units(sample_bytes, &init)?;
                samples.push(ExtractedMp4Sample {
                    sample_index: u64::from(seq),
                    media_pts_ns: timing.pts_ns(init.timescale),
                    idr_nal_units: idr_nals,
                    in_band_parameter_sets: in_band,
                });
            }
            idx += 1;
        }
        if samples.is_empty() {
            return Err(VantageError::invalid_container(
                "fragmented MP4 contained zero sync samples",
            ));
        }
        return Ok((init, samples));
    }

    // 2. Progressive MP4 (`moov` sample table `stts`/`stsc`/`stsz`/`stco`/`co64`/`stss`).
    let moov = top_boxes
        .iter()
        .find(|b| &b.box_type == b"moov")
        .ok_or_else(|| VantageError::invalid_container("MP4 missing 'moov' box"))?;
    let moov_children = scan_boxes(moov.payload)?;
    for trak in moov_children.iter().filter(|b| &b.box_type == b"trak") {
        let trak_children = scan_boxes(trak.payload)?;
        let Some(mdia) = trak_children.iter().find(|b| &b.box_type == b"mdia") else {
            continue;
        };
        let mdia_children = scan_boxes(mdia.payload)?;
        if let Some(hdlr) = mdia_children.iter().find(|b| &b.box_type == b"hdlr")
            && hdlr.payload.len() >= 12
            && &hdlr.payload[8..12] != b"vide"
        {
            continue;
        }
        let Some(minf) = mdia_children.iter().find(|b| &b.box_type == b"minf") else {
            continue;
        };
        let minf_children = scan_boxes(minf.payload)?;
        let Some(stbl) = minf_children.iter().find(|b| &b.box_type == b"stbl") else {
            continue;
        };
        let stbl_children = scan_boxes(stbl.payload)?;
        let samples = extract_progressive_sync_samples(mp4_bytes, &init, &stbl_children)?;
        if !samples.is_empty() {
            return Ok((init, samples));
        }
    }

    Err(VantageError::invalid_container(
        "MP4 file contained no decodable video sync samples",
    ))
}

fn extract_progressive_sync_samples(
    mp4_bytes: &[u8],
    init: &ParsedInitSegment,
    stbl_children: &[BoxView<'_>],
) -> Result<Vec<ExtractedMp4Sample>, VantageError> {
    let stsz = stbl_children
        .iter()
        .find(|b| &b.box_type == b"stsz")
        .ok_or_else(|| VantageError::invalid_container("MP4 'stbl' missing 'stsz' box"))?;
    let stsc = stbl_children
        .iter()
        .find(|b| &b.box_type == b"stsc")
        .ok_or_else(|| VantageError::invalid_container("MP4 'stbl' missing 'stsc' box"))?;

    let sample_sizes = parse_stsz(stsz.payload)?;
    if sample_sizes.is_empty() {
        return Err(VantageError::invalid_container("MP4 'stsz' has 0 samples"));
    }

    let chunk_offsets = if let Some(stco) = stbl_children.iter().find(|b| &b.box_type == b"stco") {
        parse_stco(stco.payload)?
    } else if let Some(co64) = stbl_children.iter().find(|b| &b.box_type == b"co64") {
        parse_co64(co64.payload)?
    } else {
        return Err(VantageError::invalid_container(
            "MP4 'stbl' missing 'stco' or 'co64' box",
        ));
    };

    let stsc_entries = parse_stsc(stsc.payload)?;
    let sample_offsets = compute_sample_offsets(&sample_sizes, &chunk_offsets, &stsc_entries)?;

    let sample_dts = if let Some(stts) = stbl_children.iter().find(|b| &b.box_type == b"stts") {
        parse_stts_dts(stts.payload, sample_sizes.len())?
    } else {
        vec![0u64; sample_sizes.len()]
    };

    let sync_indices: Vec<usize> =
        if let Some(stss) = stbl_children.iter().find(|b| &b.box_type == b"stss") {
            parse_stss(stss.payload, sample_sizes.len())?
        } else {
            vec![0]
        };

    let mut out = Vec::with_capacity(sync_indices.len());
    for idx in sync_indices {
        let off = usize::try_from(sample_offsets[idx])
            .map_err(|_| VantageError::invalid_container("sample offset overflows usize"))?;
        let sz = usize::try_from(sample_sizes[idx])
            .map_err(|_| VantageError::invalid_container("sample size overflows usize"))?;
        let end = off
            .checked_add(sz)
            .ok_or_else(|| VantageError::invalid_container("sample end overflows usize"))?;
        let slice = mp4_bytes.get(off..end).ok_or_else(|| {
            VantageError::invalid_container("progressive MP4 sample range exceeds file bounds")
        })?;
        let (idr_nals, in_band) = extract_keyframe_nal_units(slice, init)?;
        let pts_ns = SampleTiming {
            decode_ticks: sample_dts.get(idx).copied().unwrap_or(0),
            cts_offset: 0,
        }
        .pts_ns(init.timescale);
        out.push(ExtractedMp4Sample {
            sample_index: (idx + 1) as u64,
            media_pts_ns: pts_ns,
            idr_nal_units: idr_nals,
            in_band_parameter_sets: in_band,
        });
    }
    Ok(out)
}

fn parse_stsz(payload: &[u8]) -> Result<Vec<u32>, VantageError> {
    if payload.len() < 12 {
        return Err(VantageError::invalid_container("truncated 'stsz' box"));
    }
    let uniform_size = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let count = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
    if uniform_size > 0 {
        return Ok(vec![uniform_size; count]);
    }
    if payload.len() < 12 + count * 4 {
        return Err(VantageError::invalid_container("truncated 'stsz' entries"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * 4;
        out.push(u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]));
    }
    Ok(out)
}

fn parse_stco(payload: &[u8]) -> Result<Vec<u64>, VantageError> {
    if payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'stco' box"));
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if payload.len() < 8 + count * 4 {
        return Err(VantageError::invalid_container("truncated 'stco' entries"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 4;
        out.push(u64::from(u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ])));
    }
    Ok(out)
}

fn parse_co64(payload: &[u8]) -> Result<Vec<u64>, VantageError> {
    if payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'co64' box"));
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if payload.len() < 8 + count * 8 {
        return Err(VantageError::invalid_container("truncated 'co64' entries"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 8;
        out.push(u64::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]));
    }
    Ok(out)
}

fn parse_stsc(payload: &[u8]) -> Result<Vec<(u32, u32)>, VantageError> {
    if payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'stsc' box"));
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if payload.len() < 8 + count * 12 {
        return Err(VantageError::invalid_container("truncated 'stsc' entries"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 12;
        let first_chunk = u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]);
        let samples_per_chunk = u32::from_be_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]);
        out.push((first_chunk, samples_per_chunk));
    }
    Ok(out)
}

fn compute_sample_offsets(
    sample_sizes: &[u32],
    chunk_offsets: &[u64],
    stsc_entries: &[(u32, u32)],
) -> Result<Vec<u64>, VantageError> {
    let mut out = Vec::with_capacity(sample_sizes.len());
    let mut sample_idx = 0usize;
    let mut stsc_idx = 0usize;

    for (chunk_zero, &chunk_offset) in chunk_offsets.iter().enumerate() {
        let chunk_one = (chunk_zero + 1) as u32;
        while stsc_idx + 1 < stsc_entries.len() && stsc_entries[stsc_idx + 1].0 <= chunk_one {
            stsc_idx += 1;
        }
        let samples_in_chunk = stsc_entries.get(stsc_idx).map(|e| e.1).unwrap_or(1);
        let mut cursor = chunk_offset;
        for _ in 0..samples_in_chunk {
            if sample_idx >= sample_sizes.len() {
                break;
            }
            out.push(cursor);
            cursor = cursor.saturating_add(u64::from(sample_sizes[sample_idx]));
            sample_idx += 1;
        }
        if sample_idx >= sample_sizes.len() {
            break;
        }
    }
    if out.len() != sample_sizes.len() {
        return Err(VantageError::invalid_container(
            "MP4 sample-to-chunk table does not cover all samples",
        ));
    }
    Ok(out)
}

fn parse_stts_dts(payload: &[u8], sample_count: usize) -> Result<Vec<u64>, VantageError> {
    if payload.len() < 8 {
        return Ok(vec![0; sample_count]);
    }
    let entry_count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let mut out = Vec::with_capacity(sample_count);
    let mut dts = 0u64;
    for i in 0..entry_count {
        let off = 8 + i * 8;
        if off + 8 > payload.len() {
            break;
        }
        let count = u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]);
        let delta = u32::from_be_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]);
        for _ in 0..count {
            if out.len() >= sample_count {
                break;
            }
            out.push(dts);
            dts = dts.saturating_add(u64::from(delta));
        }
    }
    while out.len() < sample_count {
        out.push(dts);
    }
    Ok(out)
}

fn parse_stss(payload: &[u8], sample_count: usize) -> Result<Vec<usize>, VantageError> {
    if payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'stss' box"));
    }
    let count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    if payload.len() < 8 + count * 4 {
        return Err(VantageError::invalid_container("truncated 'stss' entries"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 4;
        let one_based = u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]) as usize;
        if one_based >= 1 && one_based <= sample_count {
            out.push(one_based - 1);
        }
    }
    if out.is_empty() && sample_count > 0 {
        out.push(0);
    }
    Ok(out)
}

fn parse_mvhd_or_mdhd_timescale(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    let ts_offset = match payload[0] {
        0 => 12,
        1 => 20,
        _ => return None,
    };
    if payload.len() < ts_offset + 4 {
        return None;
    }
    let ts = u32::from_be_bytes([
        payload[ts_offset],
        payload[ts_offset + 1],
        payload[ts_offset + 2],
        payload[ts_offset + 3],
    ]);
    (ts > 0).then_some(ts)
}

fn parse_tkhd_dimensions(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < 4 {
        return None;
    }
    let dim_offset = match payload[0] {
        0 => 76usize,
        1 => 88usize,
        _ => return None,
    };
    if payload.len() < dim_offset + 8 {
        return None;
    }
    let width_fixed = u32::from_be_bytes([
        payload[dim_offset],
        payload[dim_offset + 1],
        payload[dim_offset + 2],
        payload[dim_offset + 3],
    ]);
    let height_fixed = u32::from_be_bytes([
        payload[dim_offset + 4],
        payload[dim_offset + 5],
        payload[dim_offset + 6],
        payload[dim_offset + 7],
    ]);
    Some((width_fixed >> 16, height_fixed >> 16))
}

fn parse_video_trak(
    trak_payload: &[u8],
    default_timescale: u32,
) -> Result<Option<ParsedInitSegment>, VantageError> {
    let trak_children = scan_boxes(trak_payload)?;
    let tkhd_dims = trak_children
        .iter()
        .find(|b| &b.box_type == b"tkhd")
        .and_then(|b| parse_tkhd_dimensions(b.payload));

    let Some(mdia) = trak_children.iter().find(|b| &b.box_type == b"mdia") else {
        return Ok(None);
    };
    let mdia_children = scan_boxes(mdia.payload)?;

    let mut timescale = default_timescale;
    if let Some(mdhd) = mdia_children.iter().find(|b| &b.box_type == b"mdhd")
        && let Some(ts) = parse_mvhd_or_mdhd_timescale(mdhd.payload)
    {
        timescale = ts;
    }

    if let Some(hdlr) = mdia_children.iter().find(|b| &b.box_type == b"hdlr")
        && hdlr.payload.len() >= 12
        && &hdlr.payload[8..12] != b"vide"
    {
        return Ok(None);
    }

    let Some(minf) = mdia_children.iter().find(|b| &b.box_type == b"minf") else {
        return Ok(None);
    };
    let minf_children = scan_boxes(minf.payload)?;
    let Some(stbl) = minf_children.iter().find(|b| &b.box_type == b"stbl") else {
        return Ok(None);
    };
    let stbl_children = scan_boxes(stbl.payload)?;
    let Some(stsd) = stbl_children.iter().find(|b| &b.box_type == b"stsd") else {
        return Ok(None);
    };

    parse_stsd(stsd.payload, timescale, tkhd_dims)
}

fn parse_stsd(
    stsd_payload: &[u8],
    timescale: u32,
    tkhd_dims: Option<(u32, u32)>,
) -> Result<Option<ParsedInitSegment>, VantageError> {
    if stsd_payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'stsd' box"));
    }
    let entry_count = u32::from_be_bytes([
        stsd_payload[4],
        stsd_payload[5],
        stsd_payload[6],
        stsd_payload[7],
    ]);
    if entry_count == 0 {
        return Ok(None);
    }

    let entries = scan_boxes(&stsd_payload[8..])?;
    for entry in entries {
        let codec = match &entry.box_type {
            b"avc1" | b"avc3" => VideoCodec::H264,
            b"hvc1" | b"hev1" => VideoCodec::Hevc,
            _ => continue,
        };
        if entry.payload.len() < 78 {
            return Err(VantageError::invalid_container(
                "truncated VisualSampleEntry (< 78 bytes)",
            ));
        }
        let sample_w = u32::from(u16::from_be_bytes([entry.payload[24], entry.payload[25]]));
        let sample_h = u32::from(u16::from_be_bytes([entry.payload[26], entry.payload[27]]));
        let (fallback_w, fallback_h) = tkhd_dims.unwrap_or((0, 0));
        let width = if sample_w > 0 { sample_w } else { fallback_w };
        let height = if sample_h > 0 { sample_h } else { fallback_h };

        if width == 0 || height == 0 {
            return Err(VantageError::invalid_container(format!(
                "invalid video sample dimensions {width}x{height}"
            )));
        }

        let config_boxes = scan_boxes(&entry.payload[78..])?;
        match codec {
            VideoCodec::H264 => {
                let avcc = config_boxes
                    .iter()
                    .find(|b| &b.box_type == b"avcC")
                    .ok_or_else(|| {
                        VantageError::invalid_container("avc1/avc3 sample entry missing 'avcC' box")
                    })?;
                let (nal_length_size, parameter_sets) = parse_avcc(avcc.payload)?;
                return Ok(Some(ParsedInitSegment {
                    codec,
                    in_band_avc_sets: &entry.box_type == b"avc3",
                    width,
                    height,
                    timescale,
                    nal_length_size,
                    parameter_sets,
                }));
            }
            VideoCodec::Hevc => {
                let hvcc = config_boxes
                    .iter()
                    .find(|b| &b.box_type == b"hvcC")
                    .ok_or_else(|| {
                        VantageError::invalid_container("hvc1/hev1 sample entry missing 'hvcC' box")
                    })?;
                let (nal_length_size, parameter_sets) = parse_hvcc(hvcc.payload)?;
                return Ok(Some(ParsedInitSegment {
                    codec,
                    in_band_avc_sets: false,
                    width,
                    height,
                    timescale,
                    nal_length_size,
                    parameter_sets,
                }));
            }
        }
    }

    Ok(None)
}

fn parse_avcc(payload: &[u8]) -> Result<(u8, Vec<Vec<u8>>), VantageError> {
    if payload.len() < 7 || payload[0] != 1 {
        return Err(VantageError::invalid_container(
            "invalid or truncated AVCDecoderConfigurationRecord ('avcC')",
        ));
    }
    let nal_length_size = (payload[4] & 0x03) + 1;
    if nal_length_size == 3 {
        return Err(VantageError::invalid_container(
            "unsupported 3-byte NAL length size in avcC",
        ));
    }
    let num_sps = usize::from(payload[5] & 0x1f);
    let mut cursor = 6usize;
    let mut param_sets = Vec::new();

    for _ in 0..num_sps {
        if cursor + 2 > payload.len() {
            return Err(VantageError::invalid_container("truncated SPS in avcC"));
        }
        let len = usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
        cursor += 2;
        if cursor + len > payload.len() {
            return Err(VantageError::invalid_container("SPS length exceeds avcC"));
        }
        param_sets.push(payload[cursor..cursor + len].to_vec());
        cursor += len;
    }

    if cursor >= payload.len() {
        return Err(VantageError::invalid_container("missing PPS count in avcC"));
    }
    let num_pps = usize::from(payload[cursor]);
    cursor += 1;
    for _ in 0..num_pps {
        if cursor + 2 > payload.len() {
            return Err(VantageError::invalid_container("truncated PPS in avcC"));
        }
        let len = usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
        cursor += 2;
        if cursor + len > payload.len() {
            return Err(VantageError::invalid_container("PPS length exceeds avcC"));
        }
        param_sets.push(payload[cursor..cursor + len].to_vec());
        cursor += len;
    }

    Ok((nal_length_size, param_sets))
}

fn parse_hvcc(payload: &[u8]) -> Result<(u8, Vec<Vec<u8>>), VantageError> {
    if payload.len() < 23 || payload[0] != 1 {
        return Err(VantageError::invalid_container(
            "invalid or truncated HEVCDecoderConfigurationRecord ('hvcC')",
        ));
    }
    let nal_length_size = (payload[21] & 0x03) + 1;
    if nal_length_size == 3 {
        return Err(VantageError::invalid_container(
            "unsupported 3-byte NAL length size in hvcC",
        ));
    }
    let num_arrays = usize::from(payload[22]);
    let mut cursor = 23usize;
    let mut param_sets = Vec::new();

    for _ in 0..num_arrays {
        if cursor + 3 > payload.len() {
            return Err(VantageError::invalid_container("truncated array in hvcC"));
        }
        let num_nalus = usize::from(u16::from_be_bytes([
            payload[cursor + 1],
            payload[cursor + 2],
        ]));
        cursor += 3;
        for _ in 0..num_nalus {
            if cursor + 2 > payload.len() {
                return Err(VantageError::invalid_container("truncated NALU in hvcC"));
            }
            let len = usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
            cursor += 2;
            if cursor + len > payload.len() {
                return Err(VantageError::invalid_container("NALU length exceeds hvcC"));
            }
            param_sets.push(payload[cursor..cursor + len].to_vec());
            cursor += len;
        }
    }

    Ok((nal_length_size, param_sets))
}

/// Parses a single CMAF `media.m4s` fragment (`moof` + `mdat`).
pub fn parse_media_fragment(
    fragment_bytes: &[u8],
    init: &ParsedInitSegment,
) -> Result<ParsedMediaFragment, VantageError> {
    if init.width > MAX_FRAME_DIMENSION || init.height > MAX_FRAME_DIMENSION {
        return Err(VantageError::decode(
            "limit_exceeded",
            "container picture exceeds dimension limit",
        ));
    }
    let boxes = scan_boxes(fragment_bytes)?;
    let moof = boxes
        .iter()
        .find(|b| &b.box_type == b"moof")
        .ok_or_else(|| VantageError::invalid_container("CMAF fragment missing 'moof' box"))?;
    let mdat = boxes
        .iter()
        .find(|b| &b.box_type == b"mdat")
        .ok_or_else(|| VantageError::invalid_container("CMAF fragment missing 'mdat' box"))?;

    let mut timing = SampleTiming {
        decode_ticks: 0,
        cts_offset: 0,
    };
    let (sequence_number, sample_bytes) = parse_moof_mdat(moof.payload, mdat.payload, &mut timing)?;
    let (idr_nal_units, in_band_parameter_sets) = extract_keyframe_nal_units(sample_bytes, init)?;
    Ok(ParsedMediaFragment {
        sequence_number,
        timing,
        first_sample_size: sample_bytes.len(),
        idr_nal_units,
        in_band_parameter_sets,
    })
}

fn parse_moof_mdat<'a>(
    moof_payload: &[u8],
    mdat_payload: &'a [u8],
    timing: &mut SampleTiming,
) -> Result<(u32, &'a [u8]), VantageError> {
    let moof_children = scan_boxes(moof_payload)?;
    let sequence_number = moof_children
        .iter()
        .find(|b| &b.box_type == b"mfhd")
        .and_then(|b| {
            (b.payload.len() >= 8).then(|| {
                u32::from_be_bytes([b.payload[4], b.payload[5], b.payload[6], b.payload[7]])
            })
        })
        .unwrap_or(0);

    let traf = moof_children
        .iter()
        .find(|b| &b.box_type == b"traf")
        .ok_or_else(|| VantageError::invalid_container("CMAF 'moof' missing 'traf' box"))?;
    let traf_children = scan_boxes(traf.payload)?;

    let default_sample_size = traf_children
        .iter()
        .find(|b| &b.box_type == b"tfhd")
        .and_then(|b| parse_tfhd_default_sample_size(b.payload));

    timing.decode_ticks = traf_children
        .iter()
        .find(|b| &b.box_type == b"tfdt")
        .and_then(|b| parse_tfdt(b.payload))
        .unwrap_or(0);

    let trun = traf_children
        .iter()
        .find(|b| &b.box_type == b"trun")
        .ok_or_else(|| VantageError::invalid_container("CMAF 'traf' missing 'trun' box"))?;

    let sample = parse_trun_first_sample(trun.payload, default_sample_size)?;
    timing.cts_offset = sample.cts_offset;
    if !sample.sync {
        return Err(VantageError::invalid_container(
            "first sample in CMAF fragment is non-sync",
        ));
    }
    let size = sample.size.map_or(mdat_payload.len(), |s| s as usize);
    let bytes = mdat_payload
        .get(..size)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| {
            VantageError::invalid_container(format!(
                "invalid first sample size {size} for mdat payload"
            ))
        })?;
    Ok((sequence_number, bytes))
}

fn parse_tfhd_default_sample_size(payload: &[u8]) -> Option<u32> {
    if payload.len() < 8 {
        return None;
    }
    let flags = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
    let mut cursor = 8usize;
    if flags & 0x000001 != 0 {
        cursor += 8;
    }
    if flags & 0x000002 != 0 {
        cursor += 4;
    }
    if flags & 0x000008 != 0 {
        cursor += 4;
    }
    if flags & 0x000010 != 0 {
        if cursor + 4 > payload.len() {
            return None;
        }
        return Some(u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]));
    }
    None
}

fn parse_tfdt(payload: &[u8]) -> Option<u64> {
    if payload.len() < 8 {
        return None;
    }
    match payload[0] {
        0 => Some(u64::from(u32::from_be_bytes([
            payload[4], payload[5], payload[6], payload[7],
        ]))),
        1 if payload.len() >= 12 => Some(u64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ])),
        _ => None,
    }
}

struct FirstSample {
    size: Option<u32>,
    sync: bool,
    cts_offset: i64,
}

fn parse_trun_first_sample(
    payload: &[u8],
    default_sample_size: Option<u32>,
) -> Result<FirstSample, VantageError> {
    if payload.len() < 8 {
        return Err(VantageError::invalid_container("truncated 'trun' box"));
    }
    let version = payload[0];
    let flags = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
    let sample_count = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if sample_count == 0 {
        return Err(VantageError::invalid_container(
            "'trun' box contains 0 samples",
        ));
    }

    let mut sync = true;
    let mut cursor = 8usize;
    if flags & 0x000001 != 0 {
        cursor += 4;
    }
    if flags & 0x000004 != 0 {
        if cursor + 4 > payload.len() {
            return Err(VantageError::invalid_container(
                "truncated first_sample_flags in 'trun'",
            ));
        }
        let first_flags = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        sync = first_flags & 0x0001_0000 == 0;
        cursor += 4;
    }
    if flags & 0x000100 != 0 {
        cursor += 4;
    }
    let sample_size = if flags & 0x000200 != 0 {
        if cursor + 4 > payload.len() {
            return Err(VantageError::invalid_container(
                "truncated sample_size in 'trun'",
            ));
        }
        let sz = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        cursor += 4;
        Some(sz)
    } else {
        default_sample_size
    };
    if flags & 0x000400 != 0 {
        if cursor + 4 > payload.len() {
            return Err(VantageError::invalid_container(
                "truncated sample_flags in 'trun'",
            ));
        }
        let sample_flags = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        if flags & 0x000004 == 0 {
            sync = sample_flags & 0x0001_0000 == 0;
        }
        cursor += 4;
    }
    let cts_offset = if flags & 0x000800 != 0 {
        if cursor + 4 > payload.len() {
            return Err(VantageError::invalid_container(
                "truncated sample_composition_time_offset in 'trun'",
            ));
        }
        let raw = [
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ];
        if version == 0 {
            i64::from(u32::from_be_bytes(raw))
        } else {
            i64::from(i32::from_be_bytes(raw))
        }
    } else {
        0
    };

    Ok(FirstSample {
        size: sample_size,
        cts_offset,
        sync,
    })
}

type ExtractedNals = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn extract_keyframe_nal_units(
    sample_bytes: &[u8],
    init: &ParsedInitSegment,
) -> Result<ExtractedNals, VantageError> {
    let nal_length_size = init.nal_length_size;
    let codec = init.codec;
    let len_bytes = usize::from(nal_length_size);
    let mut cursor = 0usize;
    let mut idr_nals = Vec::new();
    let mut parameter_sets = Vec::new();
    let mut nal_count = 0usize;

    while cursor < sample_bytes.len() {
        nal_count += 1;
        if nal_count > MAX_SAMPLE_NAL_UNITS {
            return Err(VantageError::decode(
                "limit_exceeded",
                format!("keyframe sample holds more than {MAX_SAMPLE_NAL_UNITS} NAL units"),
            ));
        }
        if cursor + len_bytes > sample_bytes.len() {
            return Err(VantageError::invalid_container(
                "truncated length-prefixed NAL unit header in mdat",
            ));
        }
        let nal_len = match nal_length_size {
            1 => usize::from(sample_bytes[cursor]),
            2 => usize::from(u16::from_be_bytes([
                sample_bytes[cursor],
                sample_bytes[cursor + 1],
            ])),
            4 => u32::from_be_bytes([
                sample_bytes[cursor],
                sample_bytes[cursor + 1],
                sample_bytes[cursor + 2],
                sample_bytes[cursor + 3],
            ]) as usize,
            other => {
                return Err(VantageError::invalid_container(format!(
                    "unsupported NAL length size {other}"
                )));
            }
        };
        cursor += len_bytes;
        if nal_len == 0 || cursor + nal_len > sample_bytes.len() {
            return Err(VantageError::invalid_container(
                "NAL unit length in mdat exceeds sample boundary",
            ));
        }
        let nal = &sample_bytes[cursor..cursor + nal_len];
        cursor += nal_len;

        if is_idr_nal(nal, codec) {
            idr_nals.push(nal.to_vec());
        } else if codec == VideoCodec::H264 {
            if nal[0] & 0x80 != 0 {
                return Err(VantageError::decode(
                    "malformed_bitstream",
                    "invalid H.264 NAL header",
                ));
            }
            match nal[0] & 0x1f {
                19..=21 => {
                    return Err(VantageError::decode(
                        "unsupported_codec",
                        "auxiliary or extension coded slice",
                    ));
                }
                7 | 8 if !init.in_band_avc_sets => {}
                7 | 8 if idr_nals.is_empty() => parameter_sets.push(nal.to_vec()),
                1..=4 | 7 | 8 => {
                    return Err(VantageError::decode(
                        "malformed_bitstream",
                        "unexpected slice or parameter set in IDR sample",
                    ));
                }
                _ => {}
            }
        }
    }

    if idr_nals.is_empty() {
        return Err(VantageError::decode(
            "malformed_bitstream",
            "MP4/CMAF sample contains no IDR keyframe NAL unit",
        ));
    }
    Ok((idr_nals, parameter_sets))
}

fn is_idr_nal(nal: &[u8], codec: VideoCodec) -> bool {
    if nal.is_empty() {
        return false;
    }
    match codec {
        VideoCodec::H264 => (nal[0] & 0x80) == 0 && (nal[0] & 0x1f) == 5,
        VideoCodec::Hevc => {
            if nal.len() < 2 {
                return false;
            }
            let forbidden_zero = nal[0] & 0x80;
            let nal_type = (nal[0] >> 1) & 0x3f;
            forbidden_zero == 0 && matches!(nal_type, 16..=21)
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic CMAF Container Builders (for tests & local synthetic generation)
// ---------------------------------------------------------------------------

fn mp4_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(payload);
    out
}

fn mp4_full_box(box_type: &[u8; 4], version: u8, flags: u32, body: &[u8]) -> Vec<u8> {
    let total = (12 + body.len()) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(box_type);
    let vf = ((u32::from(version)) << 24) | (flags & 0x00ff_ffff);
    out.extend_from_slice(&vf.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn build_avcc_box(sps: &[&[u8]], pps: &[&[u8]]) -> Vec<u8> {
    let profile = sps
        .first()
        .and_then(|s| s.get(1..4))
        .unwrap_or(&[0x42, 0x00, 0x1f]);
    let mut body = vec![1, profile[0], profile[1], profile[2], 0xff];
    body.push(0xe0 | (sps.len() as u8 & 0x1f));
    for nal in sps {
        body.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        body.extend_from_slice(nal);
    }
    body.push(pps.len() as u8);
    for nal in pps {
        body.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        body.extend_from_slice(nal);
    }
    mp4_box(b"avcC", &body)
}

pub fn build_cmaf_init_mp4(
    width: u32,
    height: u32,
    timescale: u32,
    sps: &[&[u8]],
    pps: &[&[u8]],
) -> Vec<u8> {
    let config_box = build_avcc_box(sps, pps);

    let mut ftyp_body = Vec::with_capacity(24);
    ftyp_body.extend_from_slice(b"cmfc");
    ftyp_body.extend_from_slice(&0u32.to_be_bytes());
    ftyp_body.extend_from_slice(b"cmfciso6avc1mp41");
    let ftyp = mp4_box(b"ftyp", &ftyp_body);

    let mut mvhd_body = vec![0u8; 96];
    mvhd_body[8..12].copy_from_slice(&timescale.to_be_bytes());
    mvhd_body[16..20].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    mvhd_body[20..22].copy_from_slice(&0x0100u16.to_be_bytes());
    mvhd_body[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    mvhd_body[48..52].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    mvhd_body[64..68].copy_from_slice(&0x4000_0000u32.to_be_bytes());
    mvhd_body[92..96].copy_from_slice(&2u32.to_be_bytes());
    let mvhd = mp4_full_box(b"mvhd", 0, 0, &mvhd_body);

    let mut tkhd_body = vec![0u8; 80];
    tkhd_body[8..12].copy_from_slice(&1u32.to_be_bytes());
    tkhd_body[36..40].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    tkhd_body[52..56].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    tkhd_body[68..72].copy_from_slice(&0x4000_0000u32.to_be_bytes());
    tkhd_body[72..76].copy_from_slice(&(width << 16).to_be_bytes());
    tkhd_body[76..80].copy_from_slice(&(height << 16).to_be_bytes());
    let tkhd = mp4_full_box(b"tkhd", 0, 0x000003, &tkhd_body);

    let mut mdhd_body = vec![0u8; 20];
    mdhd_body[8..12].copy_from_slice(&timescale.to_be_bytes());
    mdhd_body[16..18].copy_from_slice(&0x55c4u16.to_be_bytes());
    let mdhd = mp4_full_box(b"mdhd", 0, 0, &mdhd_body);

    let mut hdlr_body = Vec::with_capacity(25);
    hdlr_body.extend_from_slice(&0u32.to_be_bytes());
    hdlr_body.extend_from_slice(b"vide");
    hdlr_body.extend_from_slice(&[0u8; 12]);
    hdlr_body.extend_from_slice(b"VideoHandler\0");
    let hdlr = mp4_full_box(b"hdlr", 0, 0, &hdlr_body);

    let mut avc1_body = vec![0u8; 78];
    avc1_body[6..8].copy_from_slice(&1u16.to_be_bytes());
    avc1_body[24..26].copy_from_slice(&(width as u16).to_be_bytes());
    avc1_body[26..28].copy_from_slice(&(height as u16).to_be_bytes());
    avc1_body[28..32].copy_from_slice(&0x0048_0000u32.to_be_bytes());
    avc1_body[32..36].copy_from_slice(&0x0048_0000u32.to_be_bytes());
    avc1_body[40..42].copy_from_slice(&1u16.to_be_bytes());
    avc1_body[74..76].copy_from_slice(&0x0018u16.to_be_bytes());
    avc1_body[76..78].copy_from_slice(&0xffffu16.to_be_bytes());
    avc1_body.extend_from_slice(&config_box);
    let avc1 = mp4_box(b"avc1", &avc1_body);

    let mut stsd_body = Vec::with_capacity(4 + avc1.len());
    stsd_body.extend_from_slice(&1u32.to_be_bytes());
    stsd_body.extend_from_slice(&avc1);
    let stsd = mp4_full_box(b"stsd", 0, 0, &stsd_body);

    let empty_count = 0u32.to_be_bytes();
    let stts = mp4_full_box(b"stts", 0, 0, &empty_count);
    let stsc = mp4_full_box(b"stsc", 0, 0, &empty_count);
    let stsz = mp4_full_box(b"stsz", 0, 0, &[0u8; 8]);
    let stco = mp4_full_box(b"stco", 0, 0, &empty_count);

    let mut stbl_body = Vec::new();
    stbl_body.extend_from_slice(&stsd);
    stbl_body.extend_from_slice(&stts);
    stbl_body.extend_from_slice(&stsc);
    stbl_body.extend_from_slice(&stsz);
    stbl_body.extend_from_slice(&stco);
    let stbl = mp4_box(b"stbl", &stbl_body);

    let vmhd = mp4_full_box(b"vmhd", 0, 1, &[0u8; 8]);
    let url_box = mp4_full_box(b"url ", 0, 1, &[]);
    let mut dref_body = Vec::with_capacity(4 + url_box.len());
    dref_body.extend_from_slice(&1u32.to_be_bytes());
    dref_body.extend_from_slice(&url_box);
    let dref = mp4_full_box(b"dref", 0, 0, &dref_body);
    let dinf = mp4_box(b"dinf", &dref);

    let mut minf_body = Vec::new();
    minf_body.extend_from_slice(&vmhd);
    minf_body.extend_from_slice(&dinf);
    minf_body.extend_from_slice(&stbl);
    let minf = mp4_box(b"minf", &minf_body);

    let mut mdia_body = Vec::new();
    mdia_body.extend_from_slice(&mdhd);
    mdia_body.extend_from_slice(&hdlr);
    mdia_body.extend_from_slice(&minf);
    let mdia = mp4_box(b"mdia", &mdia_body);

    let mut trak_body = Vec::new();
    trak_body.extend_from_slice(&tkhd);
    trak_body.extend_from_slice(&mdia);
    let trak = mp4_box(b"trak", &trak_body);

    let mut trex_body = vec![0u8; 20];
    trex_body[0..4].copy_from_slice(&1u32.to_be_bytes());
    trex_body[4..8].copy_from_slice(&1u32.to_be_bytes());
    let trex = mp4_full_box(b"trex", 0, 0, &trex_body);
    let mvex = mp4_box(b"mvex", &trex);

    let mut moov_body = Vec::new();
    moov_body.extend_from_slice(&mvhd);
    moov_body.extend_from_slice(&trak);
    moov_body.extend_from_slice(&mvex);
    let moov = mp4_box(b"moov", &moov_body);

    let mut init_mp4 = Vec::with_capacity(ftyp.len() + moov.len());
    init_mp4.extend_from_slice(&ftyp);
    init_mp4.extend_from_slice(&moov);
    init_mp4
}

pub fn build_cmaf_fragment_m4s(
    sequence: u32,
    start_ns: u64,
    duration_ns: u64,
    timescale: u32,
    sample_nals: &[&[u8]],
) -> Vec<u8> {
    let mut sample_data = Vec::new();
    for nal in sample_nals {
        sample_data.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        sample_data.extend_from_slice(nal);
    }

    let decode_ticks =
        u64::try_from(u128::from(start_ns).saturating_mul(u128::from(timescale)) / 1_000_000_000)
            .unwrap_or(0);
    let dur_ticks = u32::try_from(
        u128::from(duration_ns).saturating_mul(u128::from(timescale)) / 1_000_000_000,
    )
    .unwrap_or(timescale * 2);

    let mfhd = mp4_full_box(b"mfhd", 0, 0, &(sequence + 1).to_be_bytes());
    let tfhd = mp4_full_box(b"tfhd", 0, 0x020000, &1u32.to_be_bytes());
    let tfdt = mp4_full_box(b"tfdt", 1, 0, &decode_ticks.to_be_bytes());

    let mut trun_body = Vec::with_capacity(16);
    trun_body.extend_from_slice(&1u32.to_be_bytes());
    trun_body.extend_from_slice(&0x0200_0000u32.to_be_bytes());
    trun_body.extend_from_slice(&dur_ticks.to_be_bytes());
    trun_body.extend_from_slice(&(sample_data.len() as u32).to_be_bytes());
    let trun = mp4_full_box(b"trun", 0, 0x000304, &trun_body);

    let mut traf_body = Vec::new();
    traf_body.extend_from_slice(&tfhd);
    traf_body.extend_from_slice(&tfdt);
    traf_body.extend_from_slice(&trun);
    let traf = mp4_box(b"traf", &traf_body);

    let mut moof_body = Vec::new();
    moof_body.extend_from_slice(&mfhd);
    moof_body.extend_from_slice(&traf);
    let moof = mp4_box(b"moof", &moof_body);
    let mdat = mp4_box(b"mdat", &sample_data);

    let mut frag = Vec::with_capacity(moof.len() + mdat.len());
    frag.extend_from_slice(&moof);
    frag.extend_from_slice(&mdat);
    frag
}
