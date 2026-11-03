package internal

import (
	tester_utils_testing "github.com/codecrafters-io/tester-utils/testing"
	"testing"
)

// Verify that tester registrations match the course's stage slugs and order.
func TestStagesMatchYAML(t *testing.T) {
	// Arrange
	courseFile := "test_helpers/course_definition.yml"

	// Act and Assert
	tester_utils_testing.ValidateTesterDefinitionAgainstYAML(t, testerDefinition, courseFile)
}
