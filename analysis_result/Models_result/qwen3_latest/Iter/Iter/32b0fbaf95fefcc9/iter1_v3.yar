rule Bypass_Sample_Evolved
{
    meta:
        description = "Detects ExitProcess call with contextual prologue"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI"
        date = "2023-10-15"

    strings:
        $a = { 55 8B EC } // Function prologue
        $b = { FF 75 08 FF 15 ?? ?? ?? ?? } // Push + call (address flexible)
        $c = { FF 15 ?? ?? ?? ?? } // Direct ExitProcess call (address flexible)

    condition:
        all of ($a, $b, $c)
}