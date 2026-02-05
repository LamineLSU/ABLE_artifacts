rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion pattern involving function call and operand pushes"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF ?? ?? }
        $pattern1 = { FF 75 08 CE E8 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }
    condition:
        any of them
}