rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns identified in malware trace"
        cape_options = "$pattern0+0,action0=skip,$pattern1+0,action1=skip,$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 15 40 F1 42 00 FF 75 08 }

    condition:
        any of them
}