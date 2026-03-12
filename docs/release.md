# Release Notes

The checked-in [Key.xcodeproj](/Users/tim.vanreenen/Code/key/Key.xcodeproj) is the project source of truth.

## Build the project

```bash
scripts/build-debug-app.sh
```

This builds the checked-in [Key.xcodeproj](/Users/tim.vanreenen/Code/key/Key.xcodeproj) and leaves the app in Xcode's default DerivedData location under `~/Library/Developer/Xcode/DerivedData/...`.

For a signed archive that can exercise the entitled keychain path:

```bash
scripts/build-release-archive.sh
```

The release archive script archives the checked-in [Key.xcodeproj](/Users/tim.vanreenen/Code/key/Key.xcodeproj) with the signing identities and provisioning profiles already recorded in the project and writes the archive under `~/Library/Developer/Xcode/Archives/<date>/`.
Debug builds remain automatic or unsigned for local iteration.
The bundled CLI now lives at `Key.app/Contents/MacOS/key`, and the privileged runtime lives in `Key.app/Contents/XPCServices/KeyXPCService.xpc`.

## Verify signing inputs

```bash
scripts/verify-signing.sh "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive/Products/Applications/Key.app"
```

## Notarize and staple

```bash
scripts/notarize-release.sh "$HOME/Library/Developer/Xcode/Archives/<date>/<archive>.xcarchive"
```

The script expects `KEY_NOTARY_PROFILE` to reference a configured `notarytool` keychain profile.
