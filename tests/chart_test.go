// Copyright © 2026 Contributors
// SPDX-License-Identifier: Apache-2.0
package tests

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func render(t *testing.T, args ...string) []map[string]interface{} {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is required for offline chart tests")
	}
	command := append([]string{"template", "test", "../deploy/charts/vault-secrets-reloader", "--namespace", "infra-ns"}, args...)
	output, err := exec.Command("helm", command...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm: %v\n%s", err, output)
	}
	result := []map[string]interface{}{}
	for _, part := range strings.Split(string(output), "\n---") {
		var obj map[string]interface{}
		if err = yaml.Unmarshal([]byte(part), &obj); err != nil {
			t.Fatal(err)
		}
		if obj["kind"] != nil {
			result = append(result, obj)
		}
	}
	return result
}
func TestLegacyAndNamespacedRBAC(t *testing.T) {
	legacy := render(t)
	explicit := render(t, "--set", "mode=legacy")
	if len(legacy) != len(explicit) {
		t.Fatal("default mode is not legacy")
	}
	for _, obj := range legacy {
		if obj["kind"] == "ClusterRole" {
			rules := obj["rules"].([]interface{})
			if len(rules) != 2 {
				t.Fatal("legacy rules changed")
			}
			first := rules[0].(map[string]interface{})
			if first["verbs"].([]interface{})[2] != "update" {
				t.Fatal("legacy update permission changed")
			}
			if rules[1].(map[string]interface{})["resources"].([]interface{})[0] != "secrets" {
				t.Fatal("legacy secret permission changed")
			}
		}
		if obj["kind"] == "CustomResourceDefinition" {
			t.Fatal("legacy unexpectedly installs CRD")
		}
	}
	namespaced := render(t, "--set", "mode=namespaced", "--set", "namespaced.vaultAddressAllowlist[0]=https://vault.test", "--set", "namespaced.installCRD=true", "--set", "serviceAccount.create=false", "--set", "serviceAccount.name=existing-sa")
	roles := map[string][]interface{}{}
	bindings := []map[string]interface{}{}
	var deployment map[string]interface{}
	crds := 0
	for _, obj := range namespaced {
		switch obj["kind"] {
		case "ClusterRole":
			roles[obj["metadata"].(map[string]interface{})["name"].(string)] = obj["rules"].([]interface{})
		case "ClusterRoleBinding":
			bindings = append(bindings, obj)
		case "Deployment":
			deployment = obj
		case "CustomResourceDefinition":
			crds++
		}
	}
	if len(roles) != 2 || len(bindings) != 1 || crds != 1 {
		t.Fatalf("unexpected RBAC/CRD counts: %d %d %d", len(roles), len(bindings), crds)
	}
	bound := bindings[0]["roleRef"].(map[string]interface{})["name"].(string)
	rules := roles[bound]
	if len(rules) != 1 {
		t.Fatal("discovery binding grants more than CR access")
	}
	rule := rules[0].(map[string]interface{})
	if rule["resources"].([]interface{})[0] != "vaultreloaders" {
		t.Fatal("cluster-wide workload access")
	}
	for _, rules := range roles {
		for _, raw := range rules {
			rule := raw.(map[string]interface{})
			for _, resource := range rule["resources"].([]interface{}) {
				if resource == "secrets" || resource == "serviceaccounts/token" || resource == "*" || resource == "pods" {
					t.Fatalf("excessive permission: %s", resource)
				}
			}
		}
	}
	subject := bindings[0]["subjects"].([]interface{})[0].(map[string]interface{})
	if subject["name"] != "existing-sa" || subject["namespace"] != "infra-ns" {
		t.Fatal("existing SA override ignored")
	}
	spec := deployment["spec"].(map[string]interface{})
	rolling := spec["strategy"].(map[string]interface{})["rollingUpdate"].(map[string]interface{})
	if fmt.Sprint(rolling["maxUnavailable"]) != "1" || fmt.Sprint(rolling["maxSurge"]) != "0" {
		t.Fatal("leader must be allowed to terminate before its replacement becomes Ready")
	}
	pod := spec["template"].(map[string]interface{})["spec"].(map[string]interface{})
	args := pod["containers"].([]interface{})[0].(map[string]interface{})["command"].([]interface{})
	found := false
	for _, arg := range args {
		if arg == "--mode=namespaced" {
			found = true
		}
	}
	if !found {
		t.Fatal("RBAC and process mode disagree")
	}
}
func TestChartRejectsInvalidConfiguration(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm unavailable")
	}
	for _, args := range [][]string{{"--set", "mode=bogus"}, {"--set", "mode=namespaced"}, {"--set", "mode=namespaced", "--set", "namespaced.vaultAddressAllowlist[0]=https://vault.test", "--set", "namespaced.pollWorkers=0"}} {
		command := append([]string{"template", "test", "../deploy/charts/vault-secrets-reloader"}, args...)
		if err := exec.Command("helm", command...).Run(); err == nil {
			t.Fatalf("invalid configuration accepted: %v", args)
		}
	}
}

func TestProjectedJWTAndCustomCAVolumesRender(t *testing.T) {
	objects := render(t, "--set", "mode=namespaced", "--set", "namespaced.vaultAddressAllowlist[0]=https://vault.test", "--set", "volumes[0].name=ca", "--set", "volumes[0].configMap.name=vault-public-ca", "--set", "volumeMounts[0].name=ca", "--set", "volumeMounts[0].mountPath=/etc/vault-ca")
	for _, obj := range objects {
		if obj["kind"] != "Deployment" {
			continue
		}
		pod := obj["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
		if len(pod["volumes"].([]interface{})) != 2 {
			t.Fatal("custom volume replaced projected JWT")
		}
		container := pod["containers"].([]interface{})[0].(map[string]interface{})
		if len(container["volumeMounts"].([]interface{})) != 2 {
			t.Fatal("custom mounts replaced JWT mount")
		}
		return
	}
	t.Fatal("deployment missing")
}
