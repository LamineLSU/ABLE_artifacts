rule bypass_evasion {
    meta:
        description = "Bypasses evasion by skipping ExitProcess or prologue instructions."
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_cor_exitprocess+0,action1=skip,bp2=$prologue+0,action2=skip,count=0"
    strings:
        // Call to ExitProcess (FF 15) with wildcards for displacement
        $call_exitprocess = { FF 75 08 FF 15 ?? ?? ?? ?? }

        // Call to ___crtCorExitProcess (E8) with wildcards for displacement
        $call_cor_exitprocess = { FF 75 08 E8 C8 ?? ?? ?? }

        // Prologue instructions (push ebp, mov ebp, esp, push ebp)
        $prologue = { 55 8B EC FF 75 08 }

    condition:
        any of them
}