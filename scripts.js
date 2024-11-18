btnPost.addEventListener("click", function () {
    var containzer = document.createElement('div');
    var cghat = document.getElementById("chatContainer")
    containzer.setAttribute("id", "containerPost")
    
    
    
    var inptz = document.getElementById("input2");
    
    
    var data = inptz.textContent;
    
    
    containzer.innerHTML = data
    
    cghat.appendChild(containzer)
    
    
    
    });





    document.getElementById('Login122').addEventListener('click', function() {
        fetch('/logout', {
           method: 'POST',
           credentials: 'same-origin',
           headers: {
               'Content-Type': 'application/json'
           }
        })
        .then(response => {
           if (response.ok) {
               window.location.href = '/login'; // Redirect to login page after successful sign-out
           } else {
               alert('Failed to sign out');
           }
        })
        .catch(error => {
           console.error('Error:', error);
        });
        });
     