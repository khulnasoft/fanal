terraform {
  required_version = ">= 0.12.2"

  backend "s3" {
    region         = "eu-west-1"
    bucket         = "fanal-test-infra-state"
    key            = "terraform.tfstate"
    dynamodb_table = "fanal-test-infra-state-lock"
    encrypt        = "true"
  }
}