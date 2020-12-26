package main

import (
	"github.com/manifoldco/promptui"
)

func interactiveAssumeRole(amz *Amazon) error {
	roles, err := GetAssociatedRoles(amz)
	if err != nil {
		return err
	}
	if len(roles) == 1 {
		return assumeSingleRoleHandler(amz, roles[0])
	}

	templates := promptui.SelectTemplates{
		Active:   `🔐 {{ . | cyan | bold }}`,
		Inactive: `   {{ . | cyan }}`,
		Selected: `{{ "✔" | green | bold }} {{ "Assuming to" | bold }}: {{ . | cyan }}`,
	}

	list := promptui.Select{
		Label:     "Select a role",
		Items:     roles,
		Templates: &templates,
		Size:      len(roles),
	}

	_, selected, err := list.Run()
	if err != nil {
		panic(err)
	}

	return assumeSingleRoleHandler(amz, selected)
}
