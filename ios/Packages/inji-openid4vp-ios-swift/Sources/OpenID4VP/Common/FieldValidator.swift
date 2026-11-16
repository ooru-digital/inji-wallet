import Foundation

func isNeitherNullNorEmpty(field: String) -> Bool {
    return field != "nil" && !field.isEmpty
}

func isValidString(_ field: String) -> Bool {
    return field != "nil" && !field.isEmpty && field != "null"
}

func validateField<T>(field: T, fieldPath: [String], className: String) throws {
    if let stringValue = field as? String {
        if !isValidString(stringValue) {
            throw InvalidInput(
                fieldPath: fieldPath,
                className: className
            )
        }
    }
}

func isNullOrEmpty(_ field: String?) -> Bool {
    guard let field = field else { return true }
    return field.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || field == "nil" || field == "null"
}
