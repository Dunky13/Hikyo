package schema

// CompileWithoutCompatibilityCheckForTest exposes the compatibility-skipping
// primitive only in test builds. Engine fixtures can exercise unreachable
// declaration/classification pairs without reopening a production bypass.
func CompileWithoutCompatibilityCheckForTest(classification Classification, d Declaration) (*Compiled, error) {
	return compileWithoutCompatibilityCheckForTest(classification, d)
}

func compileWithoutCompatibilityCheckForTest(classification Classification, d Declaration) (*Compiled, error) {
	norm, err := normalizeForCompilation(classification, d)
	if err != nil {
		return nil, err
	}
	return compileNormalized(classification, norm)
}
