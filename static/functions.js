// improve chatbot button event listener
function improveQAButton(event) {
  //prevent default form submission, note that button type is submit
  event.preventDefault();

  const button = event.target;

  // get the form data in json format from inputs quesiton and answer
  const formData = Object.fromEntries(new FormData(button.form).entries());

  // add chatbot id to the form data
  const chatbotId = button.getAttribute("data-chatbot-id");
  formData.chatbot_id = chatbotId;

  // Check if the length of the question or answer exceeds 500 characters
  if (formData.question.length > 500 || formData.answer.length > 500) {
    showCustomAlert("error", "Question or Answer exceeds 500 characters", 2500);
    return; // Exit the function
  }

  // submit and improve the chatbot
  improveQA(formData);
}

// improve chatbot function
function improveQA(data) {
  // send data to /improvechatbot

  fetch("/improvebot", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success == true) {
        showCustomAlert("success", data.message, 2500);

        setTimeout(function () {
          window.location.href = data.redirect;
        }, 2500);
      } else {
        error = data.error;
        showCustomAlert("error", error, 2500);
      }
    });
}

// dynamic alert function
function showCustomAlert(type, message, timeout) {
  // setting up the alert
  const errorAlert = `  <div class="hidden transition duration-300">
            <div class=" opacity-90 fixed top-28 w-[90%] left-0 right-0 mx-auto max-w-[500px] rounded-lg z-[100] mx-auto rounded-lg bg-[#FFF0F0] p-4" role="alert">
                <p class="flex items-center text-sm font-medium text-[#BC1C21]">
                <span class="pr-3">
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="10" cy="10" r="10" fill="#BC1C21"></circle>
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M10.0002 5.54922C7.54253 5.54922 5.5502 7.54155 5.5502 9.99922C5.5502 12.4569 7.54253 14.4492 10.0002 14.4492C12.4579 14.4492 14.4502 12.4569 14.4502 9.99922C14.4502 7.54155 12.4579 5.54922 10.0002 5.54922ZM4.4502 9.99922C4.4502 6.93404 6.93502 4.44922 10.0002 4.44922C13.0654 4.44922 15.5502 6.93404 15.5502 9.99922C15.5502 13.0644 13.0654 15.5492 10.0002 15.5492C6.93502 15.5492 4.4502 13.0644 4.4502 9.99922Z" fill="white"></path>
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M10.0002 7.44922C10.304 7.44922 10.5502 7.69546 10.5502 7.99922V9.99922C10.5502 10.303 10.304 10.5492 10.0002 10.5492C9.69644 10.5492 9.4502 10.303 9.4502 9.99922V7.99922C9.4502 7.69546 9.69644 7.44922 10.0002 7.44922Z" fill="white"></path>
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M9.4502 11.9992C9.4502 11.6955 9.69644 11.4492 10.0002 11.4492H10.0052C10.309 11.4492 10.5552 11.6955 10.5552 11.9992C10.5552 12.303 10.309 12.5492 10.0052 12.5492H10.0002C9.69644 12.5492 9.4502 12.303 9.4502 11.9992Z" fill="white"></path>
                    </svg>
                </span>
                ${message}
                </p>
            </div>
        </div>`;

  const successAlert = `
    <div class="hidden transition duration-300">
<div class=" opacity-90 fixed top-28 w-[90%] left-0 right-0 mx-auto max-w-[500px] rounded-lg z-[100] mx-auto rounded-lg bg-[#C4F9E2] p-4" role="alert">
  <p class="flex items-center text-sm font-medium text-[#004434]">
     <span class="pr-3">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
           <circle cx="10" cy="10" r="10" fill="#00B078"></circle>
           <path fill-rule="evenodd" clip-rule="evenodd" d="M14.1203 6.78954C14.3865 7.05581 14.3865 7.48751 14.1203 7.75378L9.12026 12.7538C8.85399 13.02 8.42229 13.02 8.15602 12.7538L5.88329 10.4811C5.61703 10.2148 5.61703 9.78308 5.88329 9.51682C6.14956 9.25055 6.58126 9.25055 6.84753 9.51682L8.63814 11.3074L13.156 6.78954C13.4223 6.52328 13.854 6.52328 14.1203 6.78954Z" fill="white"></path>
        </svg>
     </span>
     ${message}
  </p>
</div>
</div>
    `;
  // creating the alert and making it visible
  const alert = document.createElement("div");

  if (type === "success") {
    alert.innerHTML = successAlert;
  } else if (type === "error") {
    alert.innerHTML = errorAlert;
  }

  document.body.appendChild(alert);
  const alertdiv = alert.querySelector(".hidden");

  alertdiv.classList.remove("opacity-0");
  alertdiv.classList.remove("hidden");
  setTimeout(() => {
    alertdiv.classList.add("opacity-0");
    setTimeout(() => {
      alertdiv.classList.add("hidden");
    }, 1000);
  }, timeout);
}
