<?php
namespace Neos\ACLInspector\Controller\Module;

/*
 * This file is part of the Neos.ACLInspector package.
 */

use Neos\ACLInspector\Dto\ACLCheckerDto;
use Neos\ACLInspector\Service\ACLCheckerService;
use TYPO3\Eel\FlowQuery\FlowQuery;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Policy\PolicyService;
use TYPO3\Neos\Controller\Module\AbstractModuleController;
use TYPO3\TYPO3CR\Domain\Model\NodeInterface;

class ACLInspectorController extends AbstractModuleController
{

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var ACLCheckerService
     */
    protected $aclCheckService;

    /**
     * @return void
     */
    public function indexAction(ACLCheckerDto $dto = null)
    {
        if ($dto === null) {
            $dto = new ACLCheckerDto();
        }

        $nodes = $this->aclCheckService->resolveDto($dto);

        $this->view->assignMultiple(
            [
                'dto' => $dto,
                'nodes' => $nodes,
                'roles' => $this->policyService->getRoles()
            ]
        );
    }

    /**
     * @param NodeInterface $node
     */
    public function showAction(NodeInterface $node)
    {
        $roles = $this->policyService->getRoles(true);

        $this->view->assignMultiple([
                'acl' => $this->aclCheckService->checkNodeForRoles($node, $roles),
                'targets' => $this->aclCheckService->checkPrivilegeTargetsForNodeAndRoles($node, $roles),
                'node' => $node,
                'breadcrumbNodes' => $this->breadcrumbNodesForNode($node),
                'childNodes' => $this->aclCheckService->getContentNodes($node, $roles, 999)
        ]);
    }

    /**
     * @param NodeInterface $node
     * @return array
     */
    protected function breadcrumbNodesForNode(NodeInterface $node)
    {
        $documentNodes = [];
        $flowQuery = new FlowQuery(array($node));
        $nodes = array_reverse($flowQuery->parents('[instanceof TYPO3.Neos:Document]')->get());

        /** @var NodeInterface $node */
        foreach ($nodes as $documentNode) {
            $documentNodes[] = $documentNode;
        }

        if ($node->getNodeType()->isOfType('TYPO3.Neos:Document')) {
            $documentNodes[] = $node;
        }

        return $documentNodes;
    }
}
