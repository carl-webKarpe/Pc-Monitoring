document.addEventListener('DOMContentLoaded', () => {
  const nodes = document.querySelectorAll('.node');
  nodes.forEach((node, index) => {
    node.style.animationDelay = `${index * 300}ms`;
  });
});
