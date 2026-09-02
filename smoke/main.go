package main
import ("context";"fmt";"os";"time";"github.com/appknox/appknox-go/agent")
func main(){
  cfg := agent.Config{FixURL:os.Getenv("FIX_URL"), Token:os.Getenv("FIX_TOKEN")}
  req := agent.Request{RepoRoot:os.Getenv("SMOKE_REPO"),
    ClassHint:"com/appknox/mfva/MainActivity",
    Finding:"Insecure Randomness (CWE-330): uses java.util.Random"}
  ctx,cancel := context.WithTimeout(context.Background(),150*time.Second); defer cancel()
  p,err := agent.LocateFile(ctx,cfg,req)
  if err!=nil{fmt.Fprintln(os.Stderr,"ERROR:",err);os.Exit(1)}
  fmt.Println("RESULT:", p)
}
