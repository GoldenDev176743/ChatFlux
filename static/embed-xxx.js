const currentScriptTag = document.currentScript;
const bubbleColor = currentScriptTag.getAttribute("data-bg-color") || '#5e81f7';
const chatId = currentScriptTag.getAttribute("data-chat-id");

const createChatBubble = async () => {

let src = `https://gptify.io/chatbot-iframe?chatId=${chatId}`;

    
const bubblePlacement = await fetchBubblePlacement();

const chatBubble = document.createElement("div");
chatBubble.addEventListener('click', function() {
    this.classList.toggle('active');
  });

  if (bubblePlacement === 0) {
    chatBubble.style.right = "20px";
  } else {
    chatBubble.style.left = "20px";
  }
chatBubble.style.position = "fixed";
chatBubble.style.bottom = "20px";
chatBubble.style.width = "64px";
chatBubble.style.height = "64px";
chatBubble.style.borderRadius = "32px";
chatBubble.style.backgroundColor = bubbleColor;
chatBubble.style.display = "flex";
chatBubble.style.alignItems = "center";
chatBubble.style.justifyContent = "center";
chatBubble.style.cursor = "pointer";
chatBubble.style.zIndex = "1000";
chatBubble.style.transition = "width 0.2s ease-in-out, height 0.2s ease-in-out";
chatBubble.innerHTML = `
<svg class="chat-bubble" width="100" height="100" viewBox="0 0 100 100">
<g class="bubble">
<path class="line line1" d="M 30.7873,85.113394 30.7873,46.556405 C 30.7873,41.101961
36.826342,35.342 40.898074,35.342 H 59.113981 C 63.73287,35.342
69.29995,40.103201 69.29995,46.784744" />
<path class="line line2" d="M 13.461999,65.039335 H 58.028684 C
  63.483128,65.039335
  69.243089,59.000293 69.243089,54.928561 V 45.605853 C
  69.243089,40.986964 65.02087,35.419884 58.339327,35.419884" />
</g>
<circle class="circle circle1" r="1.9" cy="50.7" cx="42.5" />
<circle class="circle circle2" cx="49.9" cy="50.7" r="1.9" />
<circle class="circle circle3" r="1.9" cy="50.7" cx="57.3" />
</svg>
<style>
.bubble {
    transform-origin: 50%;
    transition: transform 500ms cubic-bezier(0.17, 0.61, 0.54, 0.9);
}
.line {
    fill: none;
    stroke: #ffffff;
    stroke-width: 2.75;
    stroke-linecap: round;
    transition: stroke-dashoffset 500ms cubic-bezier(0.4, 0, 0.2, 1);
}
.line1 {
    stroke-dasharray: 60 90;
    stroke-dashoffset: -20;
}
.line2 {
    stroke-dasharray: 67 87;
    stroke-dashoffset: -18;
}
.circle {
    fill: #ffffff;
    stroke: none;
    transform-origin: 50%;
    transition: transform 500ms cubic-bezier(0.4, 0, 0.2, 1);
}
.active .bubble {
    transform: translateX(24px) translateY(4px) rotate(45deg);
}
.active .line1 {
    stroke-dashoffset: 21;
}
.active .line2 {
    stroke-dashoffset: 30;
}
.active .circle {
    transform: scale(0);
}
</style>`;

const iframe = document.createElement("iframe");
if (bubblePlacement === 0) {
  iframe.style.right = "20px";
} else {
  iframe.style.left = "20px";
}
iframe.src = src;
iframe.style.position = "fixed";
iframe.style.bottom = "90px";
iframe.style.width = "400px";
iframe.style.height = "500px";
iframe.style.borderRadius = "15px";
iframe.style.zIndex = "1001";
iframe.style.border = "none";
iframe.style.opacity = "0";
iframe.style.transition = "opacity 0.3s ease-in-out";
iframe.style.display = "none";


const isMobile = window.innerWidth <= 768;
if (isMobile) {
  iframe.style.width = "90%";
  iframe.style.right = "5%";
}

let isOpen = false;

chatBubble.addEventListener("click", () => {
  isOpen = !isOpen;

  if (isOpen) {
    iframe.style.display = "block";
    setTimeout(() => {
      iframe.style.opacity = "1";
    }, 200);
  } else {
    iframe.style.opacity = "0";
    setTimeout(() => {
      iframe.style.display = "none";
    }, 200);
  }

});


document.body.appendChild(chatBubble);
document.body.appendChild(iframe);

  
};
  
const fetchBubblePlacement = async () => {
  try {
    const response = await fetch(`https://gptify.io/get-bubble-placement?chatId=${chatId}`);
    const data = await response.json();
    console.log(data.bubbleplacement);
    return data.bubbleplacement;
  } catch (error) {
    console.error("Error fetching bubble placement:", error);
    return '0';
  }
};

(async () => {
  await createChatBubble();
})();