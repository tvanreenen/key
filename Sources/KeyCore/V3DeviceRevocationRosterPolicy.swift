import Foundation

/// Profile-independent roster decision only. Callers authenticate the exact
/// checkpoint/envelope before using it; this does not establish vault authority.
struct V3DeviceRevocationRosterPolicy: Sendable {
  func plan(
    checkpoint: V3ManifestCheckpoint, devices: [V3DeviceWrappedManifestDevice],
    authorizingDeviceID: String, revoking revokedDeviceID: String
  ) throws -> V3DeviceWrappedRevocationPlan {
    guard
      let owner = devices.first(where: {
        $0.identity.deviceID == authorizingDeviceID && $0.status == .active
      })
    else { throw V3DeviceWrappedRevocationPlanningError.invalidAuthorizingDevice }
    guard let revoked = devices.first(where: { $0.identity.deviceID == revokedDeviceID }) else {
      throw V3DeviceWrappedRevocationPlanningError.deviceNotFound
    }
    guard revoked.status == .active else {
      throw V3DeviceWrappedRevocationPlanningError.deviceAlreadyRevoked
    }
    let resulting = devices.map { device in
      device.identity.deviceID == revokedDeviceID
        ? V3DeviceWrappedManifestDevice(identity: device.identity, status: .revoked) : device
    }
    guard resulting.contains(where: { $0.status == .active }) else {
      throw V3DeviceWrappedRevocationPlanningError.lastActiveDevice
    }
    // The publishing Mac must retain its wrapper and exact resume authority.
    // A separate leave/handoff workflow would own different local cleanup.
    guard authorizingDeviceID != revokedDeviceID else {
      throw V3DeviceWrappedRevocationPlanningError.cannotRevokeAuthorizingDevice
    }
    return V3DeviceWrappedRevocationPlan(
      expectedCheckpoint: checkpoint, authorizingDevice: owner, revokedDevice: revoked,
      resultingDevices: resulting)
  }
}
