use image::{DynamicImage, ImageBuffer, imageops};
use imageproc::contrast::adaptive_threshold;

pub fn advanced_preprocess_image(img: &DynamicImage) -> DynamicImage {
    // Preprocessing tuned for noisy screenshots: grayscale, denoise, local threshold.
    let rgb_img = img.to_rgb8();
    
    let gray_img = imageops::grayscale(&rgb_img);
    
    let blurred = imageops::blur(&gray_img, 1.0);
    
    let thresholded = adaptive_threshold(&blurred, 7);
    
    DynamicImage::ImageLuma8(thresholded)
}

// Heavier preprocessing for scanned/photographed documents requiring stronger contrast shaping.
pub fn document_preprocess_image(img: &DynamicImage) -> DynamicImage {
    let rgb_img = img.to_rgb8();
    let gray_img = imageops::grayscale(&rgb_img);
    
    // Manual contrast stretch: pushes dark pixels darker and light pixels lighter.
    let mut contrasted = ImageBuffer::new(gray_img.width(), gray_img.height());
    for (x, y, pixel) in gray_img.enumerate_pixels() {
        let value = pixel[0];
        let enhanced_value = if value < 128 { 
            value.saturating_sub(40).max(0)
        } else { 
            value.saturating_add(40).min(255) 
        };
        contrasted.put_pixel(x, y, image::Luma([enhanced_value]));
    }
    
    // Mild blur to suppress micro‑artifacts before thresholding.
    let blurred = imageops::blur(&contrasted, 0.5);
    // Larger adaptive window for documents to handle uneven lighting.
    let thresholded = adaptive_threshold(&blurred, 11);
    
    DynamicImage::ImageLuma8(thresholded)
}

pub fn capture_screenshot() -> Result<DynamicImage, Box<dyn std::error::Error + Send + Sync>> {
    let screens = screenshots::Screen::all()?;
    let screen = screens.first().ok_or("No screens found")?;
    
    let screenshot = screen.capture()?;
    
    // Convert BGRA screenshot buffer into RGB by discarding alpha.
    let bytes = screenshot.to_vec();
    
    let mut rgb_buffer = Vec::with_capacity((screenshot.width() * screenshot.height() * 3) as usize);
    
    for chunk in bytes.chunks(4) {
        if chunk.len() == 4 {
            rgb_buffer.push(chunk[0]); // R
            rgb_buffer.push(chunk[1]); // G  
            rgb_buffer.push(chunk[2]); // B
        }
    }
    
    // Reconstruct image buffer from flattened RGB data.
    let image_buffer = ImageBuffer::from_raw(
        screenshot.width() as u32,
        screenshot.height() as u32,
        rgb_buffer,
    ).ok_or("Failed to create image buffer")?;
    
    Ok(DynamicImage::ImageRgb8(image_buffer))
}