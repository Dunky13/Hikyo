package service

import (
	"fmt"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// DesiredUser is the complete user state accepted by create and PUT. PATCH
// commands never inhabit this type: they are reduced into it before storage.
type DesiredUser struct {
	UserName   string
	ExternalID string
	// Active is already defaulted by the transport: omitted create/PUT input
	// arrives as true, while an explicit false remains false.
	Active bool
	// SubjectRaw is identity material for below-wire callers. Wire callers use
	// Attributes so the service can extract the binding's declared source.
	SubjectRaw string
	// Attributes is opaque display metadata after interpreted SCIM fields have
	// been removed.
	Attributes map[string]any
}

// UserPatchCommand is the closed set of user PATCH mutations. The private
// marker prevents transport or store packages from adding unhandled variants.
type UserPatchCommand interface {
	userPatchCommand()
}

type UserPatchSetUserName struct{ UserName string }
type UserPatchSetExternalID struct{ ExternalID string }
type UserPatchClearExternalID struct{}
type UserPatchSetActive struct{ Active bool }
type UserPatchMergeAttributes struct{ Attributes map[string]any }

func (UserPatchSetUserName) userPatchCommand()     {}
func (UserPatchSetExternalID) userPatchCommand()   {}
func (UserPatchClearExternalID) userPatchCommand() {}
func (UserPatchSetActive) userPatchCommand()       {}
func (UserPatchMergeAttributes) userPatchCommand() {}

// ReduceUserPatch applies commands sequentially without mutating current.
func ReduceUserPatch(current DesiredUser, commands []UserPatchCommand) (DesiredUser, error) {
	next := current
	next.Attributes = cloneAttributes(current.Attributes)
	for _, command := range commands {
		switch command := command.(type) {
		case UserPatchSetUserName:
			next.UserName = command.UserName
		case UserPatchSetExternalID:
			next.ExternalID = command.ExternalID
		case UserPatchClearExternalID:
			next.ExternalID = ""
		case UserPatchSetActive:
			next.Active = command.Active
		case UserPatchMergeAttributes:
			next.Attributes = mergeAttributes(next.Attributes, command.Attributes)
		default:
			return DesiredUser{}, fmt.Errorf("service: unknown SCIM user patch command %T", command)
		}
	}
	return next, nil
}

// DesiredGroup is the complete group state accepted by create and PUT.
type DesiredGroup struct {
	DisplayName string
	ExternalID  string
	Members     []string
}

// GroupPatchCommand is the closed set of group PATCH mutations.
type GroupPatchCommand interface {
	groupPatchCommand()
}

type GroupPatchSetDisplayName struct{ DisplayName string }
type GroupPatchSetExternalID struct{ ExternalID string }
type GroupPatchClearExternalID struct{}
type GroupPatchAddMembers struct{ Members []string }
type GroupPatchReplaceMembers struct{ Members []string }
type GroupPatchClearMembers struct{}
type GroupPatchRemoveMember struct{ Member string }

func (GroupPatchSetDisplayName) groupPatchCommand()  {}
func (GroupPatchSetExternalID) groupPatchCommand()   {}
func (GroupPatchClearExternalID) groupPatchCommand() {}
func (GroupPatchAddMembers) groupPatchCommand()      {}
func (GroupPatchReplaceMembers) groupPatchCommand()  {}
func (GroupPatchClearMembers) groupPatchCommand()    {}
func (GroupPatchRemoveMember) groupPatchCommand()    {}

// GroupPatchResult is the desired final state plus the reconciliation effect
// that cannot be inferred from equality: reasserting an unchanged member set
// still rebuilds origins after restore.
type GroupPatchResult struct {
	Desired        DesiredGroup
	MembersTouched bool
}

// ReduceGroupPatch applies commands sequentially without mutating current.
func ReduceGroupPatch(current DesiredGroup, commands []GroupPatchCommand) (GroupPatchResult, error) {
	result := GroupPatchResult{Desired: current}
	result.Desired.Members = dedupe(append([]string{}, current.Members...))
	for _, command := range commands {
		switch command := command.(type) {
		case GroupPatchSetDisplayName:
			result.Desired.DisplayName = command.DisplayName
		case GroupPatchSetExternalID:
			result.Desired.ExternalID = command.ExternalID
		case GroupPatchClearExternalID:
			result.Desired.ExternalID = ""
		case GroupPatchAddMembers:
			result.MembersTouched = true
			result.Desired.Members = dedupe(append(result.Desired.Members, command.Members...))
		case GroupPatchReplaceMembers:
			result.MembersTouched = true
			result.Desired.Members = dedupe(command.Members)
		case GroupPatchClearMembers:
			result.MembersTouched = true
			result.Desired.Members = nil
		case GroupPatchRemoveMember:
			result.MembersTouched = true
			members := make([]string, 0, len(result.Desired.Members))
			found := false
			for _, member := range result.Desired.Members {
				if member == command.Member {
					found = true
					continue
				}
				members = append(members, member)
			}
			if !found {
				return result, ErrSCIMNoTarget
			}
			result.Desired.Members = members
		default:
			return GroupPatchResult{}, fmt.Errorf("service: unknown SCIM group patch command %T", command)
		}
	}
	return result, nil
}

func userPatchTouchesSubjectSource(commands []UserPatchCommand, source string) bool {
	for _, command := range commands {
		switch command := command.(type) {
		case UserPatchSetUserName:
			if strings.EqualFold(source, "userName") {
				return true
			}
		case UserPatchSetExternalID, UserPatchClearExternalID:
			if strings.EqualFold(source, domain.SubjectSourceExternalID) {
				return true
			}
		case UserPatchMergeAttributes:
			if subjectSourceAttributePresent(command.Attributes, source) {
				return true
			}
		}
	}
	return false
}

func desiredUserTouchesSubjectSource(desired DesiredUser, source string) bool {
	if desired.SubjectRaw != "" {
		return true
	}
	if strings.EqualFold(source, domain.SubjectSourceExternalID) {
		return desired.ExternalID != ""
	}
	return subjectSourceAttributePresent(desired.Attributes, source)
}

func subjectSourceAttributePresent(attributes map[string]any, source string) bool {
	urn, attribute, ok := domain.SplitExtensionPath(source)
	if !ok {
		return false
	}
	_, extension, present := mapEntry(attributes, urn)
	if !present {
		return false
	}
	nested, ok := extension.(map[string]any)
	if !ok {
		return true
	}
	_, _, present = mapEntry(nested, attribute)
	return present
}

func preserveSubjectSource(desired, stored map[string]any, source string) map[string]any {
	urn, attribute, ok := domain.SplitExtensionPath(source)
	if !ok {
		return cloneAttributes(desired)
	}
	storedURN, storedExtension, present := mapEntry(stored, urn)
	if !present {
		return cloneAttributes(desired)
	}
	storedNested, ok := storedExtension.(map[string]any)
	if !ok {
		return cloneAttributes(desired)
	}
	storedAttribute, value, present := mapEntry(storedNested, attribute)
	if !present {
		return cloneAttributes(desired)
	}

	out := cloneAttributes(desired)
	if out == nil {
		out = map[string]any{}
	}
	desiredURN, desiredExtension, present := mapEntry(out, urn)
	if !present {
		desiredURN = storedURN
	}
	desiredNested, ok := desiredExtension.(map[string]any)
	if !ok {
		desiredNested = map[string]any{}
	} else {
		desiredNested = cloneAttributes(desiredNested)
	}
	desiredNested[storedAttribute] = value
	out[desiredURN] = desiredNested
	return out
}

func mapEntry(values map[string]any, name string) (string, any, bool) {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return key, value, true
		}
	}
	return "", nil, false
}

func cloneAttributes(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
