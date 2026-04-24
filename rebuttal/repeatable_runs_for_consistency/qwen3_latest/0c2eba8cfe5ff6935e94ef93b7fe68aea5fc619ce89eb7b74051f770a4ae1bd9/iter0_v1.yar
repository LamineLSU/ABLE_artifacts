rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-10"
    strings:
        $a = { 85 C0 74 12 6A 5B } // Test followed by short jump and push
        $b = { 53 FF 15 ?? ?? ?? ?? } // Push ebx followed by call to ExitProcess
        $c = { 85 C0 0F 84 ?? ?? ?? ?? } // Test followed by long jump
    condition:
        all of them
}