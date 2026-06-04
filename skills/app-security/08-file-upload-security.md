# 📁 Scan Segment 08 — File Upload Security

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Audit all file upload and file processing functionality.

Check:
- Upload validation (type, size, content inspection)
- Storage security (location, access control, URL enumeration)
- Processing risks (image parsing, document parsing, archive extraction)
- Metadata leakage from uploaded files
```

---

## Upload Validation

- Is file type validated **server-side** (not just client-side)?
- Is validation based on **content inspection** (magic bytes), not just extension?
- Can a `.php`, `.jsp`, `.aspx`, or `.py` file be uploaded and **executed**?
- Is there a **file size limit** enforced server-side?
- Can the **filename be manipulated** (path traversal via filename)?
- Are **null bytes** in filenames handled?

## Storage Security

- Are uploaded files stored **outside the web root**?
- Are files served with `Content-Disposition: attachment`?
- Are files served with the **correct Content-Type** (not guessed)?
- Is there **access control** on who can retrieve uploaded files?
- Can uploaded file URLs be **enumerated**?

## Processing Risks

| Processor | Risk |
|---|---|
| Images (ImageMagick, Sharp, Pillow) | Image parsing vulnerabilities, DoS via huge files |
| Documents (PDF, DOCX) | SSRF or XXE during parsing |
| Archives (ZIP) | Zip bomb or zip slip attacks |

## Metadata Leakage

- Are **EXIF tags stripped** from uploaded images?
- Do uploaded files retain **metadata that could leak user information**?

---

## 🛠 Technology-Specific Guidance

### Python (FastAPI / Django / Flask)
```python
import magic  # python-magic for content inspection
import os

ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "application/pdf"}
MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

async def upload_file(file: UploadFile):
    # 1. Size check
    contents = await file.read(MAX_SIZE_BYTES + 1)
    if len(contents) > MAX_SIZE_BYTES:
        raise HTTPException(413, "File too large")

    # 2. Magic bytes check — NOT file.content_type (user-controlled)
    mime = magic.from_buffer(contents[:2048], mime=True)
    if mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(400, "Invalid file type")

    # 3. Sanitize filename
    safe_name = os.path.basename(file.filename).replace("..", "")
    # 4. Store outside web root, randomize name
    storage_path = f"/var/uploads/{uuid4()}_{safe_name}"
```
- Pillow: wrap `Image.open()` in try/except and set `ImageFile.LOAD_TRUNCATED_IMAGES = False`
- For ZipFile: check `entry.filename` for `..` and absolute paths before extraction

### JavaScript / Node.js (Multer / Busboy)
```javascript
const multer = require('multer');
const fileType = require('file-type');  // magic bytes check

const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 },  // 10 MB
  fileFilter: async (req, file, cb) => {
    // file.mimetype is user-controlled — verify with magic bytes after read
    cb(null, true);
  },
  storage: multer.memoryStorage()  // keep in memory to inspect first
});

// After upload, verify magic bytes:
const type = await fileType.fromBuffer(req.file.buffer);
const ALLOWED = ['image/jpeg', 'image/png', 'application/pdf'];
if (!type || !ALLOWED.includes(type.mime)) {
  return res.status(400).json({ error: 'Invalid file type' });
}
```
- Sharp: set pixel/dimension limits before decode to prevent decompression bombs
- Zip slip in `adm-zip` / `unzipper`: validate `entry.entryName` for `../` before extraction

### Java (Spring / Quarkus)
```java
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam MultipartFile file) {
    // Size limit via @RequestParam + application.properties:
    // spring.servlet.multipart.max-file-size=10MB

    // Magic bytes check — don't trust getContentType()
    byte[] header = Arrays.copyOf(file.getBytes(), 8);
    String mime = detectMimeType(header);  // use Apache Tika

    // Sanitize filename
    String safeName = Paths.get(file.getOriginalFilename()).getFileName().toString();
    // Store outside web root
    Path dest = Paths.get("/var/uploads", UUID.randomUUID() + "_" + safeName);
    Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
}
```
- Apache Tika: `new Tika().detect(inputStream)` for reliable MIME detection
- Zip slip: check `entry.getName().startsWith("..")` for every `ZipEntry`

### .NET (ASP.NET Core — IFormFile)
```csharp
// Size limit via [RequestSizeLimit] attribute or middleware
[RequestSizeLimit(10_000_000)]
public async Task<IActionResult> Upload(IFormFile file)
{
    // Validate magic bytes — not IFormFile.ContentType (user-controlled)
    using var stream = file.OpenReadStream();
    var buffer = new byte[8];
    await stream.ReadAsync(buffer, 0, 8);
    // Check against known signatures (JPEG: FF D8 FF, PNG: 89 50 4E 47)

    // Sanitize filename
    var safeName = Path.GetFileName(file.FileName);  // strips path components
    var dest = Path.Combine("/var/uploads", Guid.NewGuid() + "_" + safeName);
    // Store outside wwwroot
}
```
- ZipArchive zip slip: `entry.FullName.Contains("..")` check before extraction

### Go
```go
// Limit read size before magic byte check
buf := make([]byte, 512)
n, _ := file.Read(buf)
contentType := http.DetectContentType(buf[:n])

allowed := map[string]bool{"image/jpeg": true, "image/png": true}
if !allowed[contentType] {
    http.Error(w, "invalid file type", http.StatusBadRequest)
    return
}

// Sanitize filename
safeName := filepath.Base(header.Filename)
// Zip slip check
if strings.Contains(entry.Name, "..") { /* reject */ }
```

### PHP (Laravel)
```php
// Laravel validation — but add mime type detection beyond extension
$request->validate([
    'file' => 'required|file|max:10240|mimes:jpeg,png,pdf',
]);

// Additional magic bytes check with finfo:
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($request->file('file')->path());
$allowed = ['image/jpeg', 'image/png', 'application/pdf'];
if (!in_array($mime, $allowed)) abort(400, 'Invalid file type');

// Store outside public directory:
$path = $request->file('file')->store('uploads', 'local');  // not 'public'
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - File types accepted by the application (images, documents, videos, archives, etc.)
# - Storage backend (local disk, S3, GCS, Azure Blob, Cloudinary, etc.)
# - Image processing library in use (Sharp, Pillow, ImageMagick, SkiaSharp, etc.)
# - Whether files are served directly or via a signed URL / controller proxy
# - Maximum file size limits currently enforced
# - Whether antivirus / malware scanning is integrated (ClamAV, etc.)
# - Whether EXIF stripping is currently done and with which library
```
