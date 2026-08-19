// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package controllerhelper

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// LogConstructorFor returns a controller-runtime-compatible LogConstructor that
// enriches the logger with controller metadata and a typed KRef key for the
// reconciled object. Unlike controller-runtime's default, it omits the flat
// "name" and "namespace" keys that duplicate the information already present
// in the typed KRef key, and it names the logger after the controller (via
// WithName, populating the dedicated "logger" field most log backends key on
// for filtering) in addition to the "controller" key-value controller-runtime's
// own default constructor already sets.
//
// Pass the same controllerName used in Named(...) and the same obj type used
// in For(...) for the controller being set up.
func LogConstructorFor(logger logr.Logger, scheme *runtime.Scheme, controllerName string, obj client.Object) func(*reconcile.Request) logr.Logger {
	gvks, _, _ := scheme.ObjectKinds(obj)
	gvk := gvks[0]
	base := logger.WithName(controllerName).WithValues(
		"controller", controllerName,
		"controllerGroup", gvk.Group,
		"controllerKind", gvk.Kind,
	)
	return func(req *reconcile.Request) logr.Logger {
		if req == nil {
			return base
		}
		return base.WithValues(gvk.Kind, klog.KRef(req.Namespace, req.Name))
	}
}
