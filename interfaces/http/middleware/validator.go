package middleware

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

type Validator interface {
	Validate(data interface{}) error
}

type validator struct {
	emailRegex *regexp.Regexp
}

func NewValidator() Validator {
	return &validator{
		emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
	}
}

func (v *validator) Validate(data interface{}) error {
	value := reflect.ValueOf(data)
	typeOf := reflect.TypeOf(data)

	if value.Kind() == reflect.Ptr {
		value = value.Elem()
		typeOf = typeOf.Elem()
	}

	if value.Kind() != reflect.Struct {
		return errors.New("validation can only be performed on structs")
	}

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := typeOf.Field(i)
		tag := fieldType.Tag.Get("validate")

		if tag == "" {
			continue
		}

		if err := v.validateField(field, fieldType.Name, tag); err != nil {
			return err
		}
	}

	return nil
}

func (v *validator) validateField(field reflect.Value, fieldName, tag string) error {
	rules := strings.Split(tag, ",")

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)

		if err := v.applyRule(field, fieldName, rule); err != nil {
			return err
		}
	}

	return nil
}

func (v *validator) applyRule(field reflect.Value, fieldName, rule string) error {
	switch {
	case rule == "required":
		return v.validateRequired(field, fieldName)
	case rule == "email":
		return v.validateEmail(field, fieldName)
	case strings.HasPrefix(rule, "min="):
		return v.validateMin(field, fieldName, rule)
	case strings.HasPrefix(rule, "max="):
		return v.validateMax(field, fieldName, rule)
	case strings.HasPrefix(rule, "oneof="):
		return v.validateOneOf(field, fieldName, rule)
	default:
		return nil
	}
}

func (v *validator) validateRequired(field reflect.Value, fieldName string) error {
	switch field.Kind() {
	case reflect.String:
		if strings.TrimSpace(field.String()) == "" {
			return fmt.Errorf("%s is required", fieldName)
		}
	case reflect.Ptr:
		if field.IsNil() {
			return fmt.Errorf("%s is required", fieldName)
		}
	case reflect.Slice, reflect.Map, reflect.Array:
		if field.Len() == 0 {
			return fmt.Errorf("%s is required", fieldName)
		}
	default:
		if field.IsZero() {
			return fmt.Errorf("%s is required", fieldName)
		}
	}
	return nil
}

func (v *validator) validateEmail(field reflect.Value, fieldName string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("%s must be a string for email validation", fieldName)
	}

	email := strings.TrimSpace(field.String())
	if email == "" {
		return nil
	}

	if !v.emailRegex.MatchString(email) {
		return fmt.Errorf("%s must be a valid email address", fieldName)
	}

	return nil
}

func (v *validator) validateMin(field reflect.Value, fieldName, rule string) error {
	minStr := strings.TrimPrefix(rule, "min=")

	switch field.Kind() {
	case reflect.String:
		var minLen int
		if _, err := fmt.Sscanf(minStr, "%d", &minLen); err != nil {
			return fmt.Errorf("invalid min rule for %s", fieldName)
		}
		if len(strings.TrimSpace(field.String())) < minLen {
			return fmt.Errorf("%s must be at least %d characters long", fieldName, minLen)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var minVal int64
		if _, err := fmt.Sscanf(minStr, "%d", &minVal); err != nil {
			return fmt.Errorf("invalid min rule for %s", fieldName)
		}
		if field.Int() < minVal {
			return fmt.Errorf("%s must be at least %d", fieldName, minVal)
		}
	}

	return nil
}

func (v *validator) validateMax(field reflect.Value, fieldName, rule string) error {
	maxStr := strings.TrimPrefix(rule, "max=")

	switch field.Kind() {
	case reflect.String:
		var maxLen int
		if _, err := fmt.Sscanf(maxStr, "%d", &maxLen); err != nil {
			return fmt.Errorf("invalid max rule for %s", fieldName)
		}
		if len(strings.TrimSpace(field.String())) > maxLen {
			return fmt.Errorf("%s must be at most %d characters long", fieldName, maxLen)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var maxVal int64
		if _, err := fmt.Sscanf(maxStr, "%d", &maxVal); err != nil {
			return fmt.Errorf("invalid max rule for %s", fieldName)
		}
		if field.Int() > maxVal {
			return fmt.Errorf("%s must be at most %d", fieldName, maxVal)
		}
	}

	return nil
}

func (v *validator) validateOneOf(field reflect.Value, fieldName, rule string) error {
	if field.Kind() != reflect.String {
		return fmt.Errorf("%s must be a string for oneof validation", fieldName)
	}

	oneofStr := strings.TrimPrefix(rule, "oneof=")
	validValues := strings.Fields(oneofStr)

	fieldValue := field.String()
	for _, validValue := range validValues {
		if fieldValue == validValue {
			return nil
		}
	}

	return fmt.Errorf("%s must be one of: %s", fieldName, strings.Join(validValues, ", "))
}