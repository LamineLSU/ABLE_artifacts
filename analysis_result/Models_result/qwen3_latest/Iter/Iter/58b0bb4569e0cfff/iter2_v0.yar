rule EvasionTechnique1
{
    meta:
        description = "Detects a suspicious test instruction with hardcoded immediate and subsequent DEC EAX"
        cape_options = "bp0=$a9_48+0,action0=skip,count=0"
    strings:
        $a9_48 = { A9 ?? ?? ?? ?? 48 }
    condition:
        $a9_48
}