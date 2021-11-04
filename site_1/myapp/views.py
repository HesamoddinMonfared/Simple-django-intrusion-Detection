from django.shortcuts import render
#import myapp.allModels
import subprocess
from django.shortcuts import redirect

# Create your views here.
def index(request):
    context = {'foo': 'bar'}
    
    if 'symbol' in request.GET:
        symbol = request.GET.get('symbol','Invalid Symbol')
        request.session['symbol'] = symbol
    else:
        #symbol = request.session['symbol']
        symbol= "asd"
            
    if request.method == 'POST' and 'run_train' in request.POST:
        process = subprocess.call(["python", "myapp\\allModels.py", "TrainMode"])

        return render(request, 'result.html', context) 
        
    elif request.method == 'POST' and 'run_test' in request.POST:
        #myapp.allModels.runModels()
        #process = subprocess.run(["python", "allModels.py", "symbol"], stdout=subprocess.PIPE)
        process = subprocess.call(["python", "myapp\\allModels.py", "TestMode"], stdout=subprocess.PIPE)
        #output = process.stdout
        #print(output)
        return render(request, 'result.html', context) 

    else:
        return render(request, 'index.html', context)
    
