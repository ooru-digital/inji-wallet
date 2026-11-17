struct TestCase<T, U> {
    let input: T
    let expectedError: String?
    let expectedCode: String?
    let expectedOutput: U?

    init(input: T, expectedError: String? = nil, expectedCode: String? = nil, expectedOutput: U? = nil) {
        self.input = input
        self.expectedError = expectedError
        self.expectedCode = expectedCode
        self.expectedOutput = expectedOutput
    }
}

extension TestCase where U == Void {
    init(input: T, expectedError: String? = nil, expectedCode: String? = nil) {
        self.init(input: input, expectedError: expectedError, expectedCode: expectedCode, expectedOutput: nil)
    }
}
