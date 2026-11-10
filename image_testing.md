# Image integration testing playbook

- Use base64-encoded images for all image-analysis requests.
- Accepted formats: JPEG, PNG, and WEBP only.
- Do not upload blank, solid-color, or uniform-variance images.
- Each test image must contain real visual features such as objects, edges, textures, or shadows.
- If an image is not PNG/JPEG/WEBP, transcode it before uploading and re-detect its MIME type.
- For animated images, extract the first frame only.
- Resize large images to reasonable bounds to avoid oversized payloads.