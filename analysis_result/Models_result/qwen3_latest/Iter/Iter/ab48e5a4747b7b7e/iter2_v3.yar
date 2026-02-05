rule EvasionCheck
{
    meta:
        description = "Detects code flow leading to process exit or cleanup"
        cape_options = "bp0=$prologue+0,action0=skip,bp1=$crt_call+0,action1=skip,bp2=$exit_call+0,action2=skip,count=0"
        author = "Malware Analyst"
        date = "2025-04-05"

    strings:
        $prologue = { 55 8B EC }  // Function entry prologue
        $crt_call = { E8 ?? ?? ?? ?? }  // Call to CRT exit function
        $exit_call = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess

    condition:
        all of them
}