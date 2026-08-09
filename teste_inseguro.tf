resource "aws_s3_bucket_acl" "teste" {
  bucket = "meu-bucket-teste"
  acl    = "public-read-write"
}