package utils

import (
	"github.com/go-playground/validator/v10"
)

func FormatValidationErrors(err error) map[string]string {
	errors := make(map[string]string)

	// Type assert to validator.ValidationErrors
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, fieldErr := range validationErrors {
			field := fieldErr.StructField()
			tag := fieldErr.Tag()
			param := fieldErr.Param()

			switch tag {
			case "required":
				errors[field] = field + " is required"
			case "min":
				errors[field] = field + " must be at least " + param + " characters"
			case "max":
				errors[field] = field + " must be at most " + param + " characters"
			case "email":
				errors[field] = field + " must be a valid email address"
			case "url":
				errors[field] = field + " must be a valid URL"
			case "oneof":
				errors[field] = field + " must be one of: " + param
			case "datetime":
				errors[field] = field + " must be in ISO 8601 format"
			default:
				errors[field] = field + " is invalid (" + tag + ")"
			}
		}
	} else {
		// Handle other errors (JSON parsing, etc.)
		errors["body"] = "Invalid request body"
	}

	return errors
}
