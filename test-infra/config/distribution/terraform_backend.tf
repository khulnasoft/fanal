terraform {
  backend "s3" {
    bucket         = "fanal-distribution-state-bucket"
    dynamodb_table = "fanal-distribution-state-bucket-lock"
    region         = "eu-west-1"
    key            = "terraform.tfstate"
  }
}
