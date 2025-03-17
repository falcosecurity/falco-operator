// Copyright (C) 2025 The Falco Authors
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

package falco

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	instancev1alpha1 "github.com/alacuku/falco-operator/api/instance/v1alpha1"
)

var _ = Describe("Falco Controller", Ordered, func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		falco := &instancev1alpha1.Falco{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Falco")
			err := k8sClient.Get(ctx, typeNamespacedName, falco)
			if err != nil && errors.IsNotFound(err) {
				resource := &instancev1alpha1.Falco{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: instancev1alpha1.FalcoSpec{
						Replicas:        nil,
						PodTemplateSpec: nil,
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &instancev1alpha1.Falco{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Falco")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &Reconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})

	Context("When creating an empty CRD", func() {
		const resourceName = "empty-crd"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		falco := &instancev1alpha1.Falco{}

		BeforeAll(func() {
			By("creating the custom resource for the Kind Falco")
			err := k8sClient.Get(ctx, typeNamespacedName, falco)
			if err != nil && errors.IsNotFound(err) {
				resource := &instancev1alpha1.Falco{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: instancev1alpha1.FalcoSpec{
						Replicas:        nil,
						PodTemplateSpec: nil,
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterAll(func() {
			resource := &instancev1alpha1.Falco{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Falco")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("type should be set to DaemonSet", func() {
			resource := &instancev1alpha1.Falco{}
			By("Getting the created resource")
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(resource.Spec.Type).To(BeEquivalentTo("DaemonSet"))
		})

		It("replicas should be set to 1", func() {
			resource := &instancev1alpha1.Falco{}
			By("Getting the created resource")
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(*resource.Spec.Replicas).To(BeEquivalentTo(1))
		})

		It("version should be set to empty string", func() {
			resource := &instancev1alpha1.Falco{}
			By("Getting the created resource")
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(resource.Spec.Version).To(BeEmpty())
		})

		It("podTemplateSpec should be set to nil", func() {
			resource := &instancev1alpha1.Falco{}
			By("Getting the created resource")
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(resource.Spec.PodTemplateSpec).To(BeNil())
		})
	})
})
