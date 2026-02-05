rule Bypass_StackManipulation
{
    meta:
        description = "Evasion bypass: Skips stack push"
        cape_options = "bp0=$pattern2+0,action0=skip,count=0"
    strings:
        $pattern2 = { 5A 8B CE E8 CE ?? ?? ?? ?? FF 15 }
    condition:
        any
}