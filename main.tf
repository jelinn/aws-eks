module "eks" {
  source  = "terraform-aws-modules/eks/aws//examples/complete"
  version = "19.4.2"
}
