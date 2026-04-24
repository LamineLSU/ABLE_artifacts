rule jne_check
{
    meta:
        description = "Bypass JNE check leading to exit"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 83 C4 14 0F 84 ?? ?? ?? ?? C3 }
    condition:
        $a
}