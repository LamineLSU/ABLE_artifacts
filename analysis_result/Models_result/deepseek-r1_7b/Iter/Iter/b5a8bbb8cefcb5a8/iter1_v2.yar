rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting EAX test before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? }  // EAX test or JE/JNE pattern
        $pattern1 = { FF 75 08 59 FF 75 08 5F 3D 00 }  // Conditional check before call
        $pattern2 = { 8B 45 F8 01 74 12 FF ?? }  // Another conditional bypass pattern

    condition:
        any of them
}