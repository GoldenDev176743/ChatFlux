// if chatbos = 0
// Display creation tutorial
function showTutorial0() {
  setTimeout(function () {
    $(document).ready(function () {
      introJs()
        .setOptions({
          tooltipPosition: "left",
          nextLabel: "Next",
          prevLabel: "Back",
          doneLabel: "Do some magic!",
          tooltipClass: "font-bold leading-tight text-gray-900",
          highlightClass: "",
          exitOnOverlayClick: true,
          dontShowAgainLabel: "Don't show this again",
          dontShowAgain: true,
          buttonClass:
            "focus:shadow-outline inline-block rounded-md border border-transparent bg-primary px-4 py-2 text-sm font-medium leading-5 text-white focus:outline-none hover:bg-indigo-500",
        })
        .onchange(function (targetElement) {
          if (this._currentStep == 0) {
            console.log("[Home] first step");
          }
          // Check if the current step is the second step
          if (this._currentStep == 1) {
            console.log("[Home] second step");
            // here we are going to display with id dropdownsources the drop down with alpine js
            document
              .getElementById("dropdownsources")
              .classList.remove("opacity-0", "invisible");
            document
              .getElementById("dropdownsources")
              .classList.add("opacity-100", "visible");
          }
        })
        .start();
    });
  }, 1000);
}

// open modal function
function openModal(chatbotId) {
  return new Promise((resolve) => {
    var modalButton = document.getElementById("settings-button-" + chatbotId);
    modalButton.click();
    setTimeout(resolve, 150); // Wait for the modal to open
  });
}

// if chatbos > 0
// Display chatbot settings tutorial
function showTutorial1(ChatbotId) {
  setTimeout(function () {
    $(document).ready(function () {
      introJs()
        .onbeforechange(async function (targetElement) {
          if (this._currentStep === 1) {
            // Open the modal and wait for it to be ready
            await openModal(ChatbotId);
          }
        })

        .setOptions({
          nextLabel: "Next",
          prevLabel: "Back",
          doneLabel: "Do some magic!",
          tooltipClass: "font-bold leading-tight text-gray-900",
          highlightClass: "",
          exitOnOverlayClick: true,
          dontShowAgainLabel: "Don't show this again",
          dontShowAgain: true,
          buttonClass:
            "focus:shadow-outline inline-block rounded-md border border-transparent bg-primary px-4 py-2 text-sm font-medium leading-5 text-white focus:outline-none hover:bg-indigo-500",
        })

        .onchange(function (targetElement) {
          if (this._currentStep == 0) {
          }
          if (this._currentStep == 1) {
          }
          if (this._currentStep == 2) {
            switchTab("appearance", ChatbotId);
          }
          if (this._currentStep == 3) {
            switchTab("update", ChatbotId);
          }
          if (this._currentStep == 4) {
            switchTab("analytics", ChatbotId);
          }
          if (this._currentStep == 5) {
            switchTab("display", ChatbotId);
          }
        })
        .start();
    });
  }, 1000);
}
