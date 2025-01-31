data "http" "fanal_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/fanal/master/README.md"
}

resource "aws_ecrpublic_repository" "fanal" {
  provider = aws.us

  repository_name = "fanal"

  catalog_data {
    description       = "A simple daemon to help you with fanal's outputs"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "fanal_ui_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/fanal-ui/master/README.md"
}

resource "aws_ecrpublic_repository" "fanal_ui" {
  provider = aws.us

  repository_name = "fanal-ui"

  catalog_data {
    description       = "A simple WebUI with latest events from Fanal"
    about_text        = substr(data.http.fanal_ui_readme.body, 0, 10240)
    architectures     = ["x86-64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "fanal_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/fanal/master/README.md"
}

resource "aws_ecrpublic_repository" "fanal" {
  provider = aws.us

  repository_name = "fanal"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "fanal_driver_loader" {
  provider = aws.us

  repository_name = "fanal-driver-loader"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "fanal_no_driver" {
  provider = aws.us

  repository_name = "fanal-no-driver"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "fanal_distroless" {
  provider = aws.us

  repository_name = "fanal-distroless"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecrpublic_repository" "fanal_driver_loader_legacy" {
  provider = aws.us

  repository_name = "fanal-driver-loader-legacy"

  catalog_data {
    description       = "Container Native Runtime Security for Cloud Native Platforms"
    about_text        = substr(data.http.fanal_readme.body, 0, 10240)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "http" "fanalctl_readme" {
  url = "https://raw.githubusercontent.com/khulnasoft/fanalctl/main/README.md"
}

resource "aws_ecrpublic_repository" "fanalctl" {
  provider = aws.us

  repository_name = "fanalctl"

  catalog_data {
    description       = "Administrative tooling for Fanal"
    about_text        = substr(data.http.fanalctl_readme.body, 0, 10200)
    architectures     = ["x86-64", "ARM 64"]
    operating_systems = ["Linux"]
  }

  lifecycle {
    prevent_destroy = true
  }
}
