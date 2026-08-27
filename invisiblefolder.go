package simple

import (
	"context"
	"encoding/json"
	"os"
	"strings"
)

const (
	invisibleDownloadPrefix = "/a/"
	invisibleMetadataPrefix = "/api/v1/files/"
	invisibleMetadataSuffix = "/metadata"
	revisionsMetadataKey    = "__revisions"
)

// InvisibleFolderCredential selects how a download authorizes against the
// file's protection. The zero value downloads a public or hidden file. Fill
// in exactly one mode: FilePassword for password-protected files, LicenseKey
// for System Locker Simple files, or Username and Password together for
// System Locker Simple files (account mode). Supplying more than one mode is
// a configuration error caught before any request.
type InvisibleFolderCredential struct {
	// FilePassword unlocks password-protected files
	// (X-Invisiblefolder-Password).
	FilePassword string

	// LicenseKey unlocks System Locker Simple files (X-Systemlocker-Key).
	LicenseKey string

	// Username and Password unlock System Locker Simple files in account
	// mode (X-Systemlocker-Username + X-Systemlocker-Password).
	Username string
	Password string
}

// headers validates the credential and maps it onto download headers.
func (c InvisibleFolderCredential) headers() (map[string]string, error) {
	modes := 0
	if c.FilePassword != "" {
		modes++
	}
	if c.LicenseKey != "" {
		modes++
	}
	if c.Username != "" || c.Password != "" {
		modes++
	}
	if modes > 1 {
		return nil, configurationError("Invisible Folder credential must use one mode: file password, license key, or username and password.")
	}
	if (c.Username == "") != (c.Password == "") {
		return nil, configurationError("Invisible Folder username and password must be supplied together.")
	}

	headers := map[string]string{}
	if c.FilePassword != "" {
		headers["X-Invisiblefolder-Password"] = c.FilePassword
	}
	if c.LicenseKey != "" {
		headers["X-Systemlocker-Key"] = c.LicenseKey
	}
	if c.Username != "" {
		headers["X-Systemlocker-Username"] = c.Username
		headers["X-Systemlocker-Password"] = c.Password
	}
	return headers, nil
}

// InvisibleFolderFile describes a file in Invisible Folder.
type InvisibleFolderFile struct {
	ID               string
	ReferenceID      string
	Name             string
	MimeType         string
	Size             uint64
	Downloads        uint64
	UploadedAt       string
	PermissionTypeID int64
}

// InvisibleFolderMetadataValue is one metadata entry.
type InvisibleFolderMetadataValue struct {
	Value     string
	CreatedAt string // empty when absent
}

// InvisibleFolderMetadata is a file description plus its metadata entries.
type InvisibleFolderMetadata struct {
	File   InvisibleFolderFile
	Values map[string]InvisibleFolderMetadataValue
}

// DownloadIfNewResult is the outcome of DownloadIfNew.
type DownloadIfNewResult struct {
	Downloaded  bool
	Revision    string
	Metadata    InvisibleFolderMetadata
	Bytes       []byte // set when downloaded to memory
	Destination string // set when downloaded to disk
}

// InvisibleFolder downloads files from Invisible Folder. Downloads use the
// end user's own credentials (or none, for public files); the token-based
// Advanced permission is a Bedrock feature and is intentionally absent.
type InvisibleFolder struct {
	client *Client
}

// InvisibleFolder returns the Invisible Folder module.
func (c *Client) InvisibleFolder() *InvisibleFolder {
	return &InvisibleFolder{client: c}
}

func validReferenceID(referenceID string) bool {
	if len(referenceID) < 4 || len(referenceID) > 128 {
		return false
	}
	for i := 0; i < len(referenceID); i++ {
		c := referenceID[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// percentEncode keeps alphanumerics and -_. unescaped and percent-encodes
// everything else with uppercase hex, matching the reference clients.
func percentEncode(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			encoded.WriteByte(c)
		default:
			encoded.WriteByte('%')
			encoded.WriteByte(hexDigits[c>>4])
			encoded.WriteByte(hexDigits[c&0x0F])
		}
	}
	return encoded.String()
}

func (f *InvisibleFolder) checkPrerequisites(referenceID string) error {
	if !strings.HasPrefix(f.client.config.InvisibleFolderBaseURL, "https://") {
		return configurationError("Invisible Folder base URL must use HTTPS.")
	}
	if !validReferenceID(referenceID) {
		return configurationError("Invisible Folder reference ID must be 4 through 128 URL-safe characters.")
	}
	return nil
}

func invisibleFileEndpoint(client *Client, prefix, referenceID string) string {
	baseURL := client.config.InvisibleFolderBaseURL
	if strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL + prefix + referenceID
}

func invisibleErrorMessage(response HTTPResponse) string {
	var parsed struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(response.Body), &parsed); err == nil {
		if parsed.Message != "" {
			return parsed.Message
		}
		if parsed.Error != "" {
			return parsed.Error
		}
	}
	return ""
}

func invisibleTransportError(action string, response HTTPResponse) *Error {
	if response.Err != nil {
		return transportError("Invisible Folder %s failed: %s", action, response.Err.Error())
	}
	return transportError("Invisible Folder %s returned HTTP %d.", action, response.StatusCode)
}

// Download fetches a file into memory. The credential selects the file's
// protection mode; the zero value downloads a public or hidden file.
func (f *InvisibleFolder) Download(ctx context.Context, referenceID string, credential InvisibleFolderCredential) ([]byte, error) {
	if err := f.checkPrerequisites(referenceID); err != nil {
		return nil, err
	}
	credentialHeaders, err := credential.headers()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"X-Invisiblefolder-Download": "1"}
	for name, value := range credentialHeaders {
		headers[name] = value
	}

	response := f.client.http.Get(ctx, invisibleFileEndpoint(f.client, invisibleDownloadPrefix, referenceID), headers)
	if !response.OK() {
		if message := invisibleErrorMessage(response); message != "" {
			return nil, transportError("Invisible Folder download failed: %s", message)
		}
		return nil, invisibleTransportError("download", response)
	}
	return []byte(response.Body), nil
}

// DownloadToFile fetches a file and writes it to destination (unencrypted).
// Parent directories are not created.
func (f *InvisibleFolder) DownloadToFile(ctx context.Context, referenceID, destination string, credential InvisibleFolderCredential) error {
	if destination == "" {
		return configurationError("Invisible Folder download destination cannot be empty.")
	}
	bytes, err := f.Download(ctx, referenceID, credential)
	if err != nil {
		return err
	}
	if writeErr := os.WriteFile(destination, bytes, 0o600); writeErr != nil {
		return &Error{Kind: ErrLocalFailure, Message: "Could not write Invisible Folder download destination."}
	}
	return nil
}

// Metadata fetches a file's description and metadata entries. keys selects
// specific entries; empty fetches all. Requires the configured API key to
// read metadata for API Available, Password Protected, and System Locker
// Simple files.
func (f *InvisibleFolder) Metadata(ctx context.Context, referenceID string, keys []string) (InvisibleFolderMetadata, error) {
	if err := f.checkPrerequisites(referenceID); err != nil {
		return InvisibleFolderMetadata{}, err
	}

	headers := map[string]string{}
	if f.client.config.InvisibleFolderAPIKey != "" {
		headers["X-Api-Key"] = f.client.config.InvisibleFolderAPIKey
	}

	requestURL := invisibleFileEndpoint(f.client, invisibleMetadataPrefix, referenceID) + invisibleMetadataSuffix
	for i, key := range keys {
		separator := "?"
		if i > 0 {
			separator = "&"
		}
		requestURL += separator + "keys[]=" + percentEncode(key)
	}

	response := f.client.http.Get(ctx, requestURL, headers)
	if !response.OK() {
		if message := invisibleErrorMessage(response); message != "" {
			return InvisibleFolderMetadata{}, transportError("Invisible Folder metadata request failed: %s", message)
		}
		return InvisibleFolderMetadata{}, invisibleTransportError("metadata request", response)
	}
	return parseInvisibleMetadata(response.Body)
}

// DownloadIfNew downloads only when the file's __revisions metadata differs
// from knownRevision. With a destination the file is written to disk;
// otherwise it is returned in memory.
func (f *InvisibleFolder) DownloadIfNew(ctx context.Context, referenceID string, knownRevision string, destination string, credential InvisibleFolderCredential) (DownloadIfNewResult, error) {
	currentMetadata, err := f.Metadata(ctx, referenceID, []string{revisionsMetadataKey})
	if err != nil {
		return DownloadIfNewResult{}, err
	}

	revision, ok := currentMetadata.Values[revisionsMetadataKey]
	if !ok {
		return DownloadIfNewResult{}, &Error{Kind: ErrServer, Message: "Invisible Folder metadata did not contain __revisions."}
	}

	result := DownloadIfNewResult{Revision: revision.Value, Metadata: currentMetadata}
	if knownRevision != "" && knownRevision == result.Revision {
		return result, nil
	}

	result.Downloaded = true
	if destination != "" {
		if err := f.DownloadToFile(ctx, referenceID, destination, credential); err != nil {
			return DownloadIfNewResult{}, err
		}
		result.Destination = destination
		return result, nil
	}
	bytes, err := f.Download(ctx, referenceID, credential)
	if err != nil {
		return DownloadIfNewResult{}, err
	}
	result.Bytes = bytes
	return result, nil
}

func parseInvisibleMetadata(body string) (InvisibleFolderMetadata, error) {
	var envelope struct {
		Data struct {
			File     json.RawMessage `json:"file"`
			Metadata map[string]struct {
				Value     string  `json:"value"`
				CreatedAt *string `json:"created_at"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || len(envelope.Data.File) == 0 || envelope.Data.Metadata == nil {
		return InvisibleFolderMetadata{}, &Error{Kind: ErrServer, Message: "Invisible Folder metadata response has the wrong shape."}
	}
	var file struct {
		ID               string `json:"id"`
		ReferenceID      string `json:"reference_id"`
		Name             string `json:"name"`
		MimeType         string `json:"mime_type"`
		Size             uint64 `json:"size"`
		Downloads        uint64 `json:"downloads"`
		UploadedAt       string `json:"uploaded_at"`
		PermissionTypeID int64  `json:"permission_type_id"`
	}
	if err := json.Unmarshal(envelope.Data.File, &file); err != nil {
		return InvisibleFolderMetadata{}, &Error{Kind: ErrServer, Message: "Invisible Folder file fields have the wrong type."}
	}
	for _, name := range []string{"id", "reference_id", "name", "mime_type", "uploaded_at"} {
		if !jsonFieldPresent(envelope.Data.File, name) {
			return InvisibleFolderMetadata{}, &Error{Kind: ErrServer, Message: "Invisible Folder file field '" + name + "' is missing."}
		}
	}

	metadata := InvisibleFolderMetadata{
		File: InvisibleFolderFile{
			ID:               file.ID,
			ReferenceID:      file.ReferenceID,
			Name:             file.Name,
			MimeType:         file.MimeType,
			Size:             file.Size,
			Downloads:        file.Downloads,
			UploadedAt:       file.UploadedAt,
			PermissionTypeID: file.PermissionTypeID,
		},
		Values: make(map[string]InvisibleFolderMetadataValue, len(envelope.Data.Metadata)),
	}
	for key, entry := range envelope.Data.Metadata {
		value := InvisibleFolderMetadataValue{Value: entry.Value}
		if entry.CreatedAt != nil {
			value.CreatedAt = *entry.CreatedAt
		}
		metadata.Values[key] = value
	}
	return metadata, nil
}

func jsonFieldPresent(raw json.RawMessage, name string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	_, ok := object[name]
	return ok
}
