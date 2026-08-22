package service

import (
	"errors"
	"reflect"
	"testing"
)

func TestReduceUserPatchAppliesCommandsInOrder(t *testing.T) {
	t.Parallel()

	current := DesiredUser{
		UserName:   "before@example.com",
		ExternalID: "subject-1",
		Active:     true,
		Attributes: map[string]any{
			"displayName": "Before",
			"title":       "Engineer",
		},
	}

	tests := []struct {
		name     string
		commands []UserPatchCommand
		want     DesiredUser
	}{
		{
			name: "later scalar and attribute commands win",
			commands: []UserPatchCommand{
				UserPatchSetActive{Active: false},
				UserPatchSetActive{Active: true},
				UserPatchSetUserName{UserName: "after@example.com"},
				UserPatchMergeAttributes{Attributes: map[string]any{"displayName": "After", "title": nil}},
			},
			want: DesiredUser{
				UserName:   "after@example.com",
				ExternalID: "subject-1",
				Active:     true,
				Attributes: map[string]any{"displayName": "After"},
			},
		},
		{
			name: "external id set then clear",
			commands: []UserPatchCommand{
				UserPatchSetExternalID{ExternalID: "subject-2"},
				UserPatchClearExternalID{},
			},
			want: DesiredUser{
				UserName:   "before@example.com",
				ExternalID: "",
				Active:     true,
				Attributes: map[string]any{"displayName": "Before", "title": "Engineer"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ReduceUserPatch(current, tt.commands)
			if err != nil {
				t.Fatalf("ReduceUserPatch: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ReduceUserPatch = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestReduceGroupPatchAppliesMembershipCommandsInOrder(t *testing.T) {
	t.Parallel()

	current := DesiredGroup{
		DisplayName: "Platform",
		ExternalID:  "group-1",
		Members:     []string{"user-a"},
	}

	tests := []struct {
		name               string
		commands           []GroupPatchCommand
		want               DesiredGroup
		wantMembersTouched bool
		wantErr            error
	}{
		{
			name: "add then remove ends without member",
			commands: []GroupPatchCommand{
				GroupPatchAddMembers{Members: []string{"user-b", "user-b"}},
				GroupPatchRemoveMember{Member: "user-b"},
			},
			want:               DesiredGroup{DisplayName: "Platform", ExternalID: "group-1", Members: []string{"user-a"}},
			wantMembersTouched: true,
		},
		{
			name: "remove then add ends with member",
			commands: []GroupPatchCommand{
				GroupPatchRemoveMember{Member: "user-a"},
				GroupPatchAddMembers{Members: []string{"user-a"}},
			},
			want:               DesiredGroup{DisplayName: "Platform", ExternalID: "group-1", Members: []string{"user-a"}},
			wantMembersTouched: true,
		},
		{
			name:               "remove missing member refuses",
			commands:           []GroupPatchCommand{GroupPatchRemoveMember{Member: "user-z"}},
			wantMembersTouched: true,
			wantErr:            ErrSCIMNoTarget,
		},
		{
			name: "replace and clear remain ordered",
			commands: []GroupPatchCommand{
				GroupPatchReplaceMembers{Members: []string{"user-b", "user-b", "user-c"}},
				GroupPatchClearMembers{},
				GroupPatchAddMembers{Members: []string{"user-d"}},
			},
			want:               DesiredGroup{DisplayName: "Platform", ExternalID: "group-1", Members: []string{"user-d"}},
			wantMembersTouched: true,
		},
		{
			name: "later scalar command wins",
			commands: []GroupPatchCommand{
				GroupPatchSetDisplayName{DisplayName: "Infrastructure"},
				GroupPatchSetExternalID{ExternalID: "group-2"},
				GroupPatchClearExternalID{},
			},
			want: DesiredGroup{DisplayName: "Infrastructure", Members: []string{"user-a"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ReduceGroupPatch(current, tt.commands)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReduceGroupPatch error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && !reflect.DeepEqual(got.Desired, tt.want) {
				t.Fatalf("ReduceGroupPatch desired = %#v, want %#v", got.Desired, tt.want)
			}
			if got.MembersTouched != tt.wantMembersTouched {
				t.Fatalf("ReduceGroupPatch MembersTouched = %v, want %v", got.MembersTouched, tt.wantMembersTouched)
			}
		})
	}
}

func TestReducersDoNotMutateCurrentDesiredState(t *testing.T) {
	t.Parallel()

	user := DesiredUser{Attributes: map[string]any{"displayName": "Before"}}
	if _, err := ReduceUserPatch(user, []UserPatchCommand{
		UserPatchMergeAttributes{Attributes: map[string]any{"displayName": "After"}},
	}); err != nil {
		t.Fatalf("ReduceUserPatch: %v", err)
	}
	if got := user.Attributes["displayName"]; got != "Before" {
		t.Fatalf("ReduceUserPatch mutated current attributes: %v", got)
	}

	group := DesiredGroup{Members: []string{"user-a"}}
	if _, err := ReduceGroupPatch(group, []GroupPatchCommand{
		GroupPatchAddMembers{Members: []string{"user-b"}},
	}); err != nil {
		t.Fatalf("ReduceGroupPatch: %v", err)
	}
	if !reflect.DeepEqual(group.Members, []string{"user-a"}) {
		t.Fatalf("ReduceGroupPatch mutated current members: %v", group.Members)
	}
}
