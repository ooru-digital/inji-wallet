public struct DeviceAuthentication {
    let signature: String
    let algorithm: String
    static let className = String(describing: DeviceAuthentication.self)
    
    public init(signature: String, algorithm: String) {
        self.signature = signature
        self.algorithm = algorithm
    }
    
    func validate() throws {
        try validateField(field: self.signature, fieldPath: ["DeviceAuthentication","signature"], className: DeviceAuthentication.className)
        try validateField(field: self.algorithm, fieldPath: ["DeviceAuthentication","algorithm"], className: DeviceAuthentication.className)
    }
    
}
