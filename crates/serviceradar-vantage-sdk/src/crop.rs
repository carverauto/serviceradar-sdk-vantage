// SPDX-License-Identifier: Apache-2.0

//! Bounded full-resolution detection and ROI crop extraction helpers.

use crate::error::VantageError;
use crate::frame::RgbFrame;
use crate::jpeg::{ThumbnailConfig, downscale_rgb_fit, encode_jpeg_thumbnail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CROP_PADDING_RATIO: f32 = 0.15;
pub const DEFAULT_MIN_BBOX_WIDTH_PX: u32 = 96;
pub const DEFAULT_MAX_CROP_DIMENSION: u32 = 640;
pub const HARD_MAX_CROP_DIMENSION: u32 = 640;
pub const DEFAULT_MAX_CROP_BYTES: usize = 96 * 1024;
pub const HARD_MAX_CROP_BYTES: usize = 96 * 1024;
pub const STORED_PREVIEW_MAX_BYTES: usize = 32 * 1024;

/// Configuration for full-resolution detection and ROI crop extraction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CropConfig {
    pub padding_ratio: f32,
    pub min_bbox_width_px: u32,
    pub min_bbox_height_px: u32,
    pub max_dimension: u32,
    pub quality: u8,
    pub min_quality: u8,
    pub max_bytes: usize,
}

impl Default for CropConfig {
    fn default() -> Self {
        Self {
            padding_ratio: DEFAULT_CROP_PADDING_RATIO,
            min_bbox_width_px: DEFAULT_MIN_BBOX_WIDTH_PX,
            min_bbox_height_px: 1,
            max_dimension: DEFAULT_MAX_CROP_DIMENSION,
            quality: 85,
            min_quality: 35,
            max_bytes: DEFAULT_MAX_CROP_BYTES,
        }
    }
}

impl CropConfig {
    /// Returns a [`CropConfig`] capped at [`STORED_PREVIEW_MAX_BYTES`] (`32 KiB`) for
    /// persisted `crop_jpeg_b64` previews.
    pub fn for_stored_preview() -> Self {
        Self {
            max_dimension: DEFAULT_MAX_CROP_DIMENSION,
            quality: 75,
            min_quality: 30,
            max_bytes: STORED_PREVIEW_MAX_BYTES,
            ..Self::default()
        }
    }

    pub fn with_bounds(mut self, max_dimension: u32, max_bytes: usize) -> Self {
        self.max_dimension = max_dimension;
        self.max_bytes = max_bytes;
        self
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        if !self.padding_ratio.is_finite() || !(0.0..=2.0).contains(&self.padding_ratio) {
            return Err(VantageError::invalid_configuration(format!(
                "crop padding_ratio {} must be finite and in 0.0..=2.0",
                self.padding_ratio
            )));
        }
        if self.max_dimension == 0 || self.max_dimension > HARD_MAX_CROP_DIMENSION {
            return Err(VantageError::invalid_configuration(format!(
                "crop max_dimension {} must be in 1..={HARD_MAX_CROP_DIMENSION}",
                self.max_dimension
            )));
        }
        if self.max_bytes < 512 || self.max_bytes > HARD_MAX_CROP_BYTES {
            return Err(VantageError::invalid_configuration(format!(
                "crop max_bytes {} must be in 512..={HARD_MAX_CROP_BYTES}",
                self.max_bytes
            )));
        }
        if self.quality == 0
            || self.quality > 100
            || self.min_quality == 0
            || self.min_quality > 100
        {
            return Err(VantageError::invalid_configuration(
                "crop quality and min_quality must be in 1..=100",
            ));
        }
        if self.min_quality > self.quality {
            return Err(VantageError::invalid_configuration(
                "crop min_quality cannot exceed quality",
            ));
        }
        Ok(())
    }

    pub fn to_thumbnail_config(&self) -> ThumbnailConfig {
        ThumbnailConfig {
            max_width: self.max_dimension,
            max_height: self.max_dimension,
            quality: self.quality,
            min_quality: self.min_quality,
            max_bytes: self.max_bytes,
        }
    }
}

/// Skip reason emitted when a detection or ROI does not satisfy crop eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CropSkipReason {
    #[serde(rename = "crop_below_min_dimension")]
    BelowMinDimension,
    #[serde(rename = "crop_outside_roi")]
    OutsideRoi,
}

impl CropSkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BelowMinDimension => "crop_below_min_dimension",
            Self::OutsideRoi => "crop_outside_roi",
        }
    }
}

/// Encoded full-resolution Baseline Sequential JFIF crop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncodedCrop {
    pub width: u32,
    pub height: u32,
    pub source_bbox_width_px: u32,
    pub source_bbox_height_px: u32,
    pub padded_bbox_norm: [f32; 4],
    pub quality: u8,
    pub jpeg_bytes: Vec<u8>,
    pub sha256_hex: String,
}

impl EncodedCrop {
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.jpeg_bytes)
    }
}

/// Result of [`crop_detection_jpeg`] and related JPEG crop helpers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CropOutcome {
    Encoded(EncodedCrop),
    Skipped {
        reason: CropSkipReason,
        bbox_width_px: u32,
        bbox_height_px: u32,
        min_bbox_width_px: u32,
    },
}

impl CropOutcome {
    pub fn encoded(&self) -> Option<&EncodedCrop> {
        match self {
            Self::Encoded(crop) => Some(crop),
            Self::Skipped { .. } => None,
        }
    }

    pub fn into_encoded(self) -> Option<EncodedCrop> {
        match self {
            Self::Encoded(crop) => Some(crop),
            Self::Skipped { .. } => None,
        }
    }
}

/// Result of [`crop_detection_rgb`] and [`crop_roi_polygon_rgb`].
#[derive(Debug, Clone, PartialEq)]
pub enum RgbCropOutcome {
    Cropped {
        frame: RgbFrame,
        source_bbox_width_px: u32,
        source_bbox_height_px: u32,
        padded_bbox_norm: [f32; 4],
    },
    Skipped {
        reason: CropSkipReason,
        bbox_width_px: u32,
        bbox_height_px: u32,
        min_bbox_width_px: u32,
    },
}

/// Normalized `[x, y]` polygon region of interest in `[0.0, 1.0]` frame coordinates.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(transparent)]
pub struct RoiPolygon(pub Vec<[f32; 2]>);

#[derive(Deserialize)]
#[serde(untagged)]
enum RoiPointRepr {
    Pair([f32; 2]),
    Object { x: f32, y: f32 },
}

impl RoiPointRepr {
    fn into_pair(self) -> [f32; 2] {
        match self {
            Self::Pair(pair) => pair,
            Self::Object { x, y } => [x, y],
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RoiPolygonRepr {
    Sequence(Vec<RoiPointRepr>),
    Map { points: Vec<RoiPointRepr> },
}

impl<'de> Deserialize<'de> for RoiPolygon {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = RoiPolygonRepr::deserialize(deserializer)?;
        let raw_points = match repr {
            RoiPolygonRepr::Sequence(pts) | RoiPolygonRepr::Map { points: pts } => pts,
        };
        Ok(Self(
            raw_points
                .into_iter()
                .map(RoiPointRepr::into_pair)
                .collect(),
        ))
    }
}

impl RoiPolygon {
    pub fn new(vertices: Vec<[f32; 2]>) -> Self {
        Self(vertices)
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        if self.0.len() < 3 {
            return Err(VantageError::invalid_configuration(format!(
                "ROI polygon requires at least 3 vertices, got {}",
                self.0.len()
            )));
        }
        for (idx, &[x, y]) in self.0.iter().enumerate() {
            if !x.is_finite()
                || !y.is_finite()
                || !(0.0..=1.0).contains(&x)
                || !(0.0..=1.0).contains(&y)
            {
                return Err(VantageError::invalid_configuration(format!(
                    "ROI polygon vertex {idx} ([{x}, {y}]) must be finite and in 0.0..=1.0"
                )));
            }
        }
        let bbox = self.bounding_bbox_unchecked();
        if bbox[2] <= bbox[0] || bbox[3] <= bbox[1] {
            return Err(VantageError::invalid_configuration(
                "ROI polygon must span non-zero width and height",
            ));
        }
        Ok(())
    }

    fn bounding_bbox_unchecked(&self) -> [f32; 4] {
        let mut min_x = 1.0f32;
        let mut min_y = 1.0f32;
        let mut max_x = 0.0f32;
        let mut max_y = 0.0f32;
        for &[x, y] in &self.0 {
            min_x = min_x.min(x.clamp(0.0, 1.0));
            min_y = min_y.min(y.clamp(0.0, 1.0));
            max_x = max_x.max(x.clamp(0.0, 1.0));
            max_y = max_y.max(y.clamp(0.0, 1.0));
        }
        [min_x, min_y, max_x, max_y]
    }

    pub fn bounding_bbox(&self) -> Result<[f32; 4], VantageError> {
        self.validate()?;
        Ok(self.bounding_bbox_unchecked())
    }

    pub fn contains_point(&self, x: f32, y: f32) -> bool {
        if self.0.len() < 3 || !x.is_finite() || !y.is_finite() {
            return false;
        }
        let n = self.0.len();
        let mut inside = false;
        for i in 0..n {
            let [x1, y1] = self.0[i];
            let [x2, y2] = self.0[(i + 1) % n];
            if point_on_segment(x, y, x1, y1, x2, y2) {
                return true;
            }
            let intersects = (y1 > y) != (y2 > y)
                && (f64::from(x)
                    < f64::from(x1)
                        + (f64::from(y) - f64::from(y1)) * (f64::from(x2) - f64::from(x1))
                            / (f64::from(y2) - f64::from(y1)));
            if intersects {
                inside = !inside;
            }
        }
        inside
    }

    pub fn overlaps_bbox(&self, bbox: [f32; 4]) -> bool {
        if self.0.len() < 3 {
            return false;
        }
        let [bx1, by1, bx2, by2] = bbox;
        if !bx1.is_finite() || !by1.is_finite() || !bx2.is_finite() || !by2.is_finite() {
            return false;
        }
        let poly_bbox = self.bounding_bbox_unchecked();
        if bx2 <= poly_bbox[0] || bx1 >= poly_bbox[2] || by2 <= poly_bbox[1] || by1 >= poly_bbox[3]
        {
            return false;
        }
        let cx = (bx1 + bx2) * 0.5;
        let cy = (by1 + by2) * 0.5;
        if self.contains_point(cx, cy)
            || self.contains_point(bx1, by1)
            || self.contains_point(bx2, by1)
            || self.contains_point(bx2, by2)
            || self.contains_point(bx1, by2)
        {
            return true;
        }
        if self
            .0
            .iter()
            .any(|&[px, py]| px >= bx1 && px <= bx2 && py >= by1 && py <= by2)
        {
            return true;
        }
        let rect_edges = [
            ([bx1, by1], [bx2, by1]),
            ([bx2, by1], [bx2, by2]),
            ([bx2, by2], [bx1, by2]),
            ([bx1, by2], [bx1, by1]),
        ];
        let n = self.0.len();
        for i in 0..n {
            let p1 = self.0[i];
            let p2 = self.0[(i + 1) % n];
            for &(r1, r2) in &rect_edges {
                if segments_intersect(p1, p2, r1, r2) {
                    return true;
                }
            }
        }
        false
    }

    pub fn mask_outside_rgb(
        &self,
        crop: &mut RgbFrame,
        crop_bbox_norm: [f32; 4],
        fill_rgb: [u8; 3],
    ) {
        let w = crop.width();
        let h = crop.height();
        if w == 0 || h == 0 {
            return;
        }
        let span_x = (crop_bbox_norm[2] - crop_bbox_norm[0]).max(0.0);
        let span_y = (crop_bbox_norm[3] - crop_bbox_norm[1]).max(0.0);
        for py in 0..h {
            let ny = crop_bbox_norm[1] + ((py as f32) + 0.5) / (h as f32) * span_y;
            for px in 0..w {
                let nx = crop_bbox_norm[0] + ((px as f32) + 0.5) / (w as f32) * span_x;
                if !self.contains_point(nx, ny) {
                    crop.set_pixel(px, py, fill_rgb);
                }
            }
        }
    }
}

fn point_on_segment(px: f32, py: f32, x1: f32, y1: f32, x2: f32, y2: f32) -> bool {
    const EPS: f64 = 1e-6;
    let cross = (f64::from(px) - f64::from(x1)) * (f64::from(y2) - f64::from(y1))
        - (f64::from(py) - f64::from(y1)) * (f64::from(x2) - f64::from(x1));
    if cross.abs() > EPS {
        return false;
    }
    let min_x = f64::from(x1.min(x2)) - EPS;
    let max_x = f64::from(x1.max(x2)) + EPS;
    let min_y = f64::from(y1.min(y2)) - EPS;
    let max_y = f64::from(y1.max(y2)) + EPS;
    let px = f64::from(px);
    let py = f64::from(py);
    px >= min_x && px <= max_x && py >= min_y && py <= max_y
}

fn segments_intersect(a1: [f32; 2], a2: [f32; 2], b1: [f32; 2], b2: [f32; 2]) -> bool {
    let orient = |p: [f32; 2], q: [f32; 2], r: [f32; 2]| -> f64 {
        (f64::from(q[0]) - f64::from(p[0])) * (f64::from(r[1]) - f64::from(p[1]))
            - (f64::from(q[1]) - f64::from(p[1])) * (f64::from(r[0]) - f64::from(p[0]))
    };
    let o1 = orient(a1, a2, b1);
    let o2 = orient(a1, a2, b2);
    let o3 = orient(b1, b2, a1);
    let o4 = orient(b1, b2, a2);

    if (o1 > 0.0 && o2 < 0.0 || o1 < 0.0 && o2 > 0.0)
        && (o3 > 0.0 && o4 < 0.0 || o3 < 0.0 && o4 > 0.0)
    {
        return true;
    }
    const EPS: f64 = 1e-9;
    (o1.abs() <= EPS && point_on_segment(b1[0], b1[1], a1[0], a1[1], a2[0], a2[1]))
        || (o2.abs() <= EPS && point_on_segment(b2[0], b2[1], a1[0], a1[1], a2[0], a2[1]))
        || (o3.abs() <= EPS && point_on_segment(a1[0], a1[1], b1[0], b1[1], b2[0], b2[1]))
        || (o4.abs() <= EPS && point_on_segment(a2[0], a2[1], b1[0], b1[1], b2[0], b2[1]))
}

fn validate_frame_and_bbox(
    frame: &RgbFrame,
    bbox_norm: [f32; 4],
) -> Result<[f32; 4], VantageError> {
    if frame.width() == 0 || frame.height() == 0 {
        return Err(VantageError::invalid_frame(
            "cannot crop from an empty frame",
        ));
    }
    let [x1, y1, x2, y2] = bbox_norm;
    if !x1.is_finite() || !y1.is_finite() || !x2.is_finite() || !y2.is_finite() {
        return Err(VantageError::invalid_frame(format!(
            "crop bbox contains non-finite coordinate: {bbox_norm:?}"
        )));
    }
    let cx1 = x1.clamp(0.0, 1.0);
    let cy1 = y1.clamp(0.0, 1.0);
    let cx2 = x2.clamp(0.0, 1.0);
    let cy2 = y2.clamp(0.0, 1.0);
    if cx2 <= cx1 || cy2 <= cy1 {
        return Err(VantageError::invalid_frame(format!(
            "crop bbox must have positive width and height, got {bbox_norm:?}"
        )));
    }
    Ok([cx1, cy1, cx2, cy2])
}

/// Expands a normalized `[x1, y1, x2, y2]` bounding box by `padding_ratio` on all sides.
pub fn expand_bbox_padded(
    bbox_norm: [f32; 4],
    padding_ratio: f32,
) -> Result<[f32; 4], VantageError> {
    if !padding_ratio.is_finite() || !(0.0..=2.0).contains(&padding_ratio) {
        return Err(VantageError::invalid_configuration(format!(
            "crop padding_ratio {padding_ratio} must be finite and in 0.0..=2.0"
        )));
    }
    let [x1, y1, x2, y2] = bbox_norm;
    if !x1.is_finite() || !y1.is_finite() || !x2.is_finite() || !y2.is_finite() {
        return Err(VantageError::invalid_frame(format!(
            "crop bbox contains non-finite coordinate: {bbox_norm:?}"
        )));
    }
    let cx1 = x1.clamp(0.0, 1.0);
    let cy1 = y1.clamp(0.0, 1.0);
    let cx2 = x2.clamp(0.0, 1.0);
    let cy2 = y2.clamp(0.0, 1.0);
    if cx2 <= cx1 || cy2 <= cy1 {
        return Err(VantageError::invalid_frame(format!(
            "crop bbox must have positive width and height, got {bbox_norm:?}"
        )));
    }
    let dx = f64::from(cx2 - cx1) * f64::from(padding_ratio);
    let dy = f64::from(cy2 - cy1) * f64::from(padding_ratio);
    Ok([
        ((f64::from(cx1) - dx).clamp(0.0, 1.0)) as f32,
        ((f64::from(cy1) - dy).clamp(0.0, 1.0)) as f32,
        ((f64::from(cx2) + dx).clamp(0.0, 1.0)) as f32,
        ((f64::from(cy2) + dy).clamp(0.0, 1.0)) as f32,
    ])
}

fn measure_unpadded_px(frame: &RgbFrame, clamped_bbox: [f32; 4]) -> (u32, u32) {
    let w_px = ((clamped_bbox[2] - clamped_bbox[0]) * (frame.width() as f32)).round() as u32;
    let h_px = ((clamped_bbox[3] - clamped_bbox[1]) * (frame.height() as f32)).round() as u32;
    (w_px, h_px)
}

pub fn crop_detection_rgb(
    frame: &RgbFrame,
    bbox_norm: [f32; 4],
    config: &CropConfig,
) -> Result<RgbCropOutcome, VantageError> {
    config.validate()?;
    let clamped = validate_frame_and_bbox(frame, bbox_norm)?;
    let (bbox_w_px, bbox_h_px) = measure_unpadded_px(frame, clamped);

    if bbox_w_px < config.min_bbox_width_px || bbox_h_px < config.min_bbox_height_px {
        return Ok(RgbCropOutcome::Skipped {
            reason: CropSkipReason::BelowMinDimension,
            bbox_width_px: bbox_w_px,
            bbox_height_px: bbox_h_px,
            min_bbox_width_px: config.min_bbox_width_px,
        });
    }

    let padded_bbox_norm = expand_bbox_padded(clamped, config.padding_ratio)?;
    let native = frame.crop_normalized(padded_bbox_norm);
    let fitted = downscale_rgb_fit(&native, config.max_dimension, config.max_dimension);

    Ok(RgbCropOutcome::Cropped {
        frame: fitted,
        source_bbox_width_px: bbox_w_px,
        source_bbox_height_px: bbox_h_px,
        padded_bbox_norm,
    })
}

pub fn crop_detection_jpeg(
    frame: &RgbFrame,
    bbox_norm: [f32; 4],
    config: &CropConfig,
) -> Result<CropOutcome, VantageError> {
    match crop_detection_rgb(frame, bbox_norm, config)? {
        RgbCropOutcome::Skipped {
            reason,
            bbox_width_px,
            bbox_height_px,
            min_bbox_width_px,
        } => Ok(CropOutcome::Skipped {
            reason,
            bbox_width_px,
            bbox_height_px,
            min_bbox_width_px,
        }),
        RgbCropOutcome::Cropped {
            frame: cropped,
            source_bbox_width_px,
            source_bbox_height_px,
            padded_bbox_norm,
        } => {
            let thumb_cfg = config.to_thumbnail_config();
            let encoded = encode_jpeg_thumbnail(&cropped, &thumb_cfg)?;
            Ok(CropOutcome::Encoded(EncodedCrop {
                width: encoded.width,
                height: encoded.height,
                source_bbox_width_px,
                source_bbox_height_px,
                padded_bbox_norm,
                quality: encoded.quality,
                jpeg_bytes: encoded.jpeg_bytes,
                sha256_hex: encoded.sha256_hex,
            }))
        }
    }
}

pub fn crop_detection_in_rois_jpeg(
    frame: &RgbFrame,
    bbox_norm: [f32; 4],
    rois: &[RoiPolygon],
    config: &CropConfig,
) -> Result<CropOutcome, VantageError> {
    config.validate()?;
    let clamped = validate_frame_and_bbox(frame, bbox_norm)?;
    for roi in rois {
        roi.validate()?;
    }
    if !rois.is_empty() && !rois.iter().any(|roi| roi.overlaps_bbox(clamped)) {
        let (bbox_width_px, bbox_height_px) = measure_unpadded_px(frame, clamped);
        return Ok(CropOutcome::Skipped {
            reason: CropSkipReason::OutsideRoi,
            bbox_width_px,
            bbox_height_px,
            min_bbox_width_px: config.min_bbox_width_px,
        });
    }
    crop_detection_jpeg(frame, clamped, config)
}

pub fn crop_roi_polygon_rgb(
    frame: &RgbFrame,
    polygon: &RoiPolygon,
    config: &CropConfig,
    mask_outside: bool,
) -> Result<RgbCropOutcome, VantageError> {
    config.validate()?;
    if frame.width() == 0 || frame.height() == 0 {
        return Err(VantageError::invalid_frame(
            "cannot crop ROI polygon from an empty frame",
        ));
    }
    let bbox_norm = polygon.bounding_bbox()?;
    let (bbox_w_px, bbox_h_px) = measure_unpadded_px(frame, bbox_norm);
    if bbox_w_px < config.min_bbox_width_px || bbox_h_px < config.min_bbox_height_px {
        return Ok(RgbCropOutcome::Skipped {
            reason: CropSkipReason::BelowMinDimension,
            bbox_width_px: bbox_w_px,
            bbox_height_px: bbox_h_px,
            min_bbox_width_px: config.min_bbox_width_px,
        });
    }

    let padded_bbox_norm = expand_bbox_padded(bbox_norm, config.padding_ratio)?;
    let mut native = frame.crop_normalized(padded_bbox_norm);
    if mask_outside {
        polygon.mask_outside_rgb(&mut native, padded_bbox_norm, [0, 0, 0]);
    }
    let fitted = downscale_rgb_fit(&native, config.max_dimension, config.max_dimension);

    Ok(RgbCropOutcome::Cropped {
        frame: fitted,
        source_bbox_width_px: bbox_w_px,
        source_bbox_height_px: bbox_h_px,
        padded_bbox_norm,
    })
}

pub fn crop_roi_polygon_jpeg(
    frame: &RgbFrame,
    polygon: &RoiPolygon,
    config: &CropConfig,
    mask_outside: bool,
) -> Result<CropOutcome, VantageError> {
    match crop_roi_polygon_rgb(frame, polygon, config, mask_outside)? {
        RgbCropOutcome::Skipped {
            reason,
            bbox_width_px,
            bbox_height_px,
            min_bbox_width_px,
        } => Ok(CropOutcome::Skipped {
            reason,
            bbox_width_px,
            bbox_height_px,
            min_bbox_width_px,
        }),
        RgbCropOutcome::Cropped {
            frame: cropped,
            source_bbox_width_px,
            source_bbox_height_px,
            padded_bbox_norm,
        } => {
            let thumb_cfg = config.to_thumbnail_config();
            let encoded = encode_jpeg_thumbnail(&cropped, &thumb_cfg)?;
            Ok(CropOutcome::Encoded(EncodedCrop {
                width: encoded.width,
                height: encoded.height,
                source_bbox_width_px,
                source_bbox_height_px,
                padded_bbox_norm,
                quality: encoded.quality,
                jpeg_bytes: encoded.jpeg_bytes,
                sha256_hex: encoded.sha256_hex,
            }))
        }
    }
}

pub fn crop_roi_polygons_jpeg(
    frame: &RgbFrame,
    polygons: &[RoiPolygon],
    config: &CropConfig,
    mask_outside: bool,
) -> Result<CropOutcome, VantageError> {
    if polygons.is_empty() {
        return Err(VantageError::invalid_configuration(
            "crop_roi_polygons_jpeg requires at least one ROI polygon",
        ));
    }
    if polygons.len() == 1 {
        return crop_roi_polygon_jpeg(frame, &polygons[0], config, mask_outside);
    }

    config.validate()?;
    if frame.width() == 0 || frame.height() == 0 {
        return Err(VantageError::invalid_frame(
            "cannot crop ROI polygons from an empty frame",
        ));
    }

    let mut union_bbox = [1.0f32, 1.0f32, 0.0f32, 0.0f32];
    for poly in polygons {
        let bbox = poly.bounding_bbox()?;
        union_bbox[0] = union_bbox[0].min(bbox[0]);
        union_bbox[1] = union_bbox[1].min(bbox[1]);
        union_bbox[2] = union_bbox[2].max(bbox[2]);
        union_bbox[3] = union_bbox[3].max(bbox[3]);
    }

    let (bbox_w_px, bbox_h_px) = measure_unpadded_px(frame, union_bbox);
    if bbox_w_px < config.min_bbox_width_px || bbox_h_px < config.min_bbox_height_px {
        return Ok(CropOutcome::Skipped {
            reason: CropSkipReason::BelowMinDimension,
            bbox_width_px: bbox_w_px,
            bbox_height_px: bbox_h_px,
            min_bbox_width_px: config.min_bbox_width_px,
        });
    }

    let padded_bbox_norm = expand_bbox_padded(union_bbox, config.padding_ratio)?;
    let mut native = frame.crop_normalized(padded_bbox_norm);
    if mask_outside {
        let w = native.width();
        let h = native.height();
        if w > 0 && h > 0 {
            let span_x = (padded_bbox_norm[2] - padded_bbox_norm[0]).max(0.0);
            let span_y = (padded_bbox_norm[3] - padded_bbox_norm[1]).max(0.0);
            for py in 0..h {
                let ny = padded_bbox_norm[1] + ((py as f32) + 0.5) / (h as f32) * span_y;
                for px in 0..w {
                    let nx = padded_bbox_norm[0] + ((px as f32) + 0.5) / (w as f32) * span_x;
                    if !polygons.iter().any(|p| p.contains_point(nx, ny)) {
                        native.set_pixel(px, py, [0, 0, 0]);
                    }
                }
            }
        }
    }
    let fitted = downscale_rgb_fit(&native, config.max_dimension, config.max_dimension);
    let thumb_cfg = config.to_thumbnail_config();
    let encoded = encode_jpeg_thumbnail(&fitted, &thumb_cfg)?;
    Ok(CropOutcome::Encoded(EncodedCrop {
        width: encoded.width,
        height: encoded.height,
        source_bbox_width_px: bbox_w_px,
        source_bbox_height_px: bbox_h_px,
        padded_bbox_norm,
        quality: encoded.quality,
        jpeg_bytes: encoded.jpeg_bytes,
        sha256_hex: encoded.sha256_hex,
    }))
}
