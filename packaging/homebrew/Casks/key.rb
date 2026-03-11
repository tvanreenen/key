cask "key" do
  version "0.1.0"
  sha256 "REPLACE_WITH_RELEASE_SHA256"

  url "https://example.com/Key.zip"
  name "Key"
  desc "Minimal macOS password CLI with biometric-backed keychain unlock"
  homepage "https://github.com/timvanreenen/key"

  app "Key.app"
  binary "Key.app/Contents/MacOS/key", target: "key"
end
