rule Pattern1 {
    meta:
        description = "Setup for CRT function call"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }
    condition:
        $a
}