rule FunctionPrologueSetup
{
    meta:
        description = "Matches the function prologue setup: push ebp, mov ebp, esp"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 8B FF 55 8B EC FF 75 08 }
    condition:
        $a
}