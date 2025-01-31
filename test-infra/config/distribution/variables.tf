variable "bucket_name" {
  type    = string
  default = "fanal-distribution"
}

variable "logging_bucket_name" {
  type    = string
  default = "logging-fanal-distribution"
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "distribution_origin_id" {
  type    = string
  default = "fanalDistributionOrigin"
}

variable "distribution_name_alias" {
  type    = string
  default = "download.khulnasoft.com"
}

variable "playground_bucket_name" {
  type = string
  default = "fanal-playground"
}

variable "playground_name_alias" {
  type = string
  default = "play.khulnasoft.com"
}

variable "playground_origin_id" {
  type = string
  default = "fanalPlaygroundOrigin"
}