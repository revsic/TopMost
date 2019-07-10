{
  "targets": [
    {
      "target_name": "topmost",
      "sources": [ "topmost.cc" ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}