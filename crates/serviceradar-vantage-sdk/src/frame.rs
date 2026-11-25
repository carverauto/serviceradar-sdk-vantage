// SPDX-License-Identifier: Apache-2.0

//! Canonical RGB8 frame, luma plane, and detection primitives.

use crate::error::VantageError;
use serde::{Deserialize, Serialize};

/// Maximum accepted width or height for a decoded frame.
pub const MAX_FRAME_DIMENSION: u32 = 8192;

/// Decoded RGB8 frame (`width * height * 3` tightly packed C-contiguous bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbFrame {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

impl RgbFrame {
    /// Creates a solid-color RGB8 frame.
    pub fn solid(width: u32, height: u32, rgb: [u8; 3]) -> Self {
        let count = (width as usize).saturating_mul(height as usize);
        let mut pixels = Vec::with_capacity(count.saturating_mul(3));
        for _ in 0..count {
            pixels.extend_from_slice(&rgb);
        }
        Self {
            width,
            height,
            pixels,
        }
    }

    /// Validates dimensions and buffer length before constructing an [`RgbFrame`].
    pub fn from_rgb8(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self, VantageError> {
        if width == 0 || height == 0 {
            return Err(VantageError::invalid_frame(format!(
                "frame dimensions must be non-zero, got {width}x{height}"
            )));
        }
        if width > MAX_FRAME_DIMENSION || height > MAX_FRAME_DIMENSION {
            return Err(VantageError::invalid_frame(format!(
                "frame dimensions {width}x{height} exceed limit {MAX_FRAME_DIMENSION}"
            )));
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(3))
            .ok_or_else(|| VantageError::invalid_frame("RGB8 frame byte length overflow"))?;
        if pixels.len() != expected {
            return Err(VantageError::invalid_frame(format!(
                "RGB8 buffer length {} != expected {} for {width}x{height}",
                pixels.len(),
                expected
            )));
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    #[inline]
    pub fn width(&self) -> u32 {
        self.width
    }

    #[inline]
    pub fn height(&self) -> u32 {
        self.height
    }

    #[inline]
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    #[inline]
    pub fn into_pixels(self) -> Vec<u8> {
        self.pixels
    }

    #[inline]
    pub fn pixel_at(&self, x: u32, y: u32) -> [u8; 3] {
        let idx = ((y as usize) * (self.width as usize) + (x as usize)) * 3;
        [self.pixels[idx], self.pixels[idx + 1], self.pixels[idx + 2]]
    }

    #[inline]
    pub fn set_pixel(&mut self, x: u32, y: u32, rgb: [u8; 3]) {
        if x < self.width && y < self.height {
            let idx = ((y as usize) * (self.width as usize) + (x as usize)) * 3;
            self.pixels[idx] = rgb[0];
            self.pixels[idx + 1] = rgb[1];
            self.pixels[idx + 2] = rgb[2];
        }
    }

    /// Paints an axis-aligned rectangle in pixel coordinates (clamped to frame bounds).
    pub fn fill_rect(&mut self, x1: u32, y1: u32, x2: u32, y2: u32, rgb: [u8; 3]) {
        let rx1 = x1.min(self.width);
        let ry1 = y1.min(self.height);
        let rx2 = x2.min(self.width);
        let ry2 = y2.min(self.height);
        for y in ry1..ry2 {
            for x in rx1..rx2 {
                self.set_pixel(x, y, rgb);
            }
        }
    }

    /// Extracts a normalized `[x1, y1, x2, y2]` sub-frame from the full-resolution image.
    pub fn crop_normalized(&self, bbox_norm: [f32; 4]) -> Self {
        let [x1, y1, x2, y2] = bbox_norm;
        let px1 = ((x1.clamp(0.0, 1.0) * (self.width as f32)).floor() as u32)
            .min(self.width.saturating_sub(1));
        let py1 = ((y1.clamp(0.0, 1.0) * (self.height as f32)).floor() as u32)
            .min(self.height.saturating_sub(1));
        let px2 =
            ((x2.clamp(0.0, 1.0) * (self.width as f32)).ceil() as u32).clamp(px1 + 1, self.width);
        let py2 =
            ((y2.clamp(0.0, 1.0) * (self.height as f32)).ceil() as u32).clamp(py1 + 1, self.height);

        let cw = px2 - px1;
        let ch = py2 - py1;
        let mut out = Vec::with_capacity((cw as usize) * (ch as usize) * 3);
        for y in py1..py2 {
            let row_start = ((y as usize) * (self.width as usize) + (px1 as usize)) * 3;
            let row_end = row_start + (cw as usize) * 3;
            out.extend_from_slice(&self.pixels[row_start..row_end]);
        }
        Self {
            width: cw,
            height: ch,
            pixels: out,
        }
    }

    /// Converts the RGB8 frame into an 8-bit BT.601 luma (`Y`) plane.
    pub fn to_luma_plane(&self) -> LumaPlane {
        let mut y_data = Vec::with_capacity((self.width as usize) * (self.height as usize));
        for px in self.pixels.as_chunks::<3>().0 {
            let y = ((77u32 * u32::from(px[0])
                + 150u32 * u32::from(px[1])
                + 29u32 * u32::from(px[2])
                + 128)
                >> 8) as u8;
            y_data.push(y);
        }
        LumaPlane {
            width: self.width,
            height: self.height,
            y: y_data,
        }
    }
}

/// Decoded 8-bit luma (`Y`) plane (`width * height` bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LumaPlane {
    width: u32,
    height: u32,
    y: Vec<u8>,
}

impl LumaPlane {
    pub fn from_y(width: u32, height: u32, y: Vec<u8>) -> Result<Self, VantageError> {
        if width == 0 || height == 0 {
            return Err(VantageError::invalid_frame(
                "luma plane dimensions must be non-zero",
            ));
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .ok_or_else(|| VantageError::invalid_frame("luma plane byte length overflow"))?;
        if y.len() != expected {
            return Err(VantageError::invalid_frame(format!(
                "luma plane length {} != expected {} for {width}x{height}",
                y.len(),
                expected
            )));
        }
        Ok(Self { width, height, y })
    }

    #[inline]
    pub fn width(&self) -> u32 {
        self.width
    }

    #[inline]
    pub fn height(&self) -> u32 {
        self.height
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.y
    }

    #[inline]
    pub fn luma_at(&self, x: u32, y: u32) -> u8 {
        self.y[(y as usize) * (self.width as usize) + (x as usize)]
    }
}

/// Canonical surveillance object categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectCategory {
    Person,
    Vehicle,
    Bicycle,
    Animal,
    Package,
    Motion,
}

impl ObjectCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Vehicle => "vehicle",
            Self::Bicycle => "bicycle",
            Self::Animal => "animal",
            Self::Package => "package",
            Self::Motion => "motion",
        }
    }

    pub fn class_id(self) -> u32 {
        match self {
            Self::Person => 0,
            Self::Vehicle => 1,
            Self::Bicycle => 2,
            Self::Animal => 3,
            Self::Package => 4,
            Self::Motion => 5,
        }
    }
}

impl core::fmt::Display for ObjectCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical object detection emitted by Stage 1 pipelines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    pub class_id: u32,
    pub label: ObjectCategory,
    pub confidence: f32,
    pub bbox: [f32; 4],
}

impl Detection {
    pub fn new(class_id: u32, label: ObjectCategory, confidence: f32, bbox: [f32; 4]) -> Self {
        Self {
            class_id,
            label,
            confidence: confidence.clamp(0.0, 1.0),
            bbox: clamp_unit_bbox(bbox),
        }
    }
}

/// Clamps a `[x1, y1, x2, y2]` box into `[0.0, 1.0]` with non-zero width and height.
pub fn clamp_unit_bbox([x1, y1, x2, y2]: [f32; 4]) -> [f32; 4] {
    let cx1 = x1.clamp(0.0, 0.999);
    let cy1 = y1.clamp(0.0, 0.999);
    let cx2 = x2.clamp(cx1 + 0.001, 1.0);
    let cy2 = y2.clamp(cy1 + 0.001, 1.0);
    [cx1, cy1, cx2, cy2]
}
