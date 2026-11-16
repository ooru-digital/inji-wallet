public struct MdocVPTokenSigningResult : VPTokenSigningResult {
    //map of docType to the signed deviceAuthenticationBytes
    let docTypeToDeviceAuthentication : [String : DeviceAuthentication]
    static let className = String(describing: MdocVPTokenSigningResult.self)
    
    public init(docTypeToDeviceAuthentication: [String: DeviceAuthentication]) {
        self.docTypeToDeviceAuthentication = docTypeToDeviceAuthentication
    }
    
    func validate() throws {
        if(docTypeToDeviceAuthentication.isEmpty) {
            throw InvalidInput(fieldPath: ["MdocVPTokenSigningResult","docTypeToDeviceAuthentication"], className: MdocVPTokenSigningResult.className)
        }
        for (_, deviceAuthentication) in docTypeToDeviceAuthentication {
            try deviceAuthentication.validate()
        }
    }
}
