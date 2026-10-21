# The publish workflow runs this on every push to main. To push by hand,
# `docker login ghcr.io` with a token that can write packages, then
# `docker buildx bake --push`.
target "default" {
  context   = "."
  platforms = ["linux/amd64", "linux/arm64"]
  tags      = ["ghcr.io/rpendleton/php-scan"]
  pull      = true
}
