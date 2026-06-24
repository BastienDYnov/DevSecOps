terraform {
  required_providers {
    kind = {
      source  = "tehcyx/kind"
      version = "~> 0.2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11.0"
    }
    # 1. AJOUT : Déclaration du provider de manipulation des manifests YAML
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.14.0"
    }
  }
}

provider "kind" {}

# Création du cluster kind
resource "kind_cluster" "default" {
  name           = "devsecops-cluster"
  wait_for_ready = true
}

# Configuration du provider Helm pour pointer sur le cluster kind
provider "helm" {
  kubernetes {
    config_path = kind_cluster.default.kubeconfig_path
  }
}

# Déploiement de Kyverno via Helm
resource "helm_release" "kyverno" {
  name             = "kyverno"
  repository       = "https://kyverno.github.io/kyverno/"
  chart            = "kyverno"
  namespace        = "kyverno"
  create_namespace = true

  depends_on = [kind_cluster.default]
}

# 2. AJOUT : Configuration du provider kubectl pour pointer sur le cluster kind
provider "kubectl" {
  config_path = kind_cluster.default.kubeconfig_path
}

# 3. MODIFICATION : Déploiement dynamique depuis le sous-dossier interne ./policies
resource "kubectl_manifest" "kyverno_policies" {
  for_each  = fileset("${path.module}/policies", "*.yaml")
  yaml_body = file("${path.module}/policies/${each.value}")

  # Attend impérativement que le moteur Kyverno et ses CRDs soient initialisés
  depends_on = [helm_release.kyverno]
}
